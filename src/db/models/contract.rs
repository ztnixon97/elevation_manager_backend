use chrono::{NaiveDate, NaiveDateTime};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use sqlx::FromRow;

#[derive(Serialize, Deserialize, Debug, FromRow, ToSchema)]
pub struct Contract {
    pub id: i32,
    pub number: String,
    pub name: String,
    pub awarding_agency: Option<String>,
    pub award_date: NaiveDate,
    pub start_date: Option<NaiveDate>,
    pub end_date: Option<NaiveDate>,
    pub modification_date: Option<NaiveDate>,
    pub modification_count: Option<i32>,
    pub latest_modification_number: Option<String>,
    pub latest_modification_reason: Option<String>,
    pub current_obligation: Option<f64>,
    pub current_spend: Option<f64>,
    pub spend_ceiling: Option<f64>,
    pub base_value: Option<f64>,
    pub funding_source: Option<String>,
    pub status: String,
    pub pop_start_date: Option<NaiveDate>,
    pub pop_end_date: Option<NaiveDate>,
    pub option_years: Option<i32>,
    pub reporting_frequency: Option<String>,
    pub last_report_date: Option<NaiveDate>,
    pub prime_contractor: Option<String>,
    pub contract_type: Option<String>,
    pub invoice_count: Option<i32>,
    pub classification: String,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

#[derive(Deserialize, ToSchema)]
pub struct NewContract {
    pub number: String,
    pub name: String,
    pub awarding_agency: Option<String>,
    pub award_date: NaiveDate,
    pub start_date: Option<NaiveDate>,
    pub end_date: Option<NaiveDate>,
    pub modification_date: Option<NaiveDate>,
    pub modification_count: Option<i32>,
    pub latest_modification_number: Option<String>,
    pub latest_modification_reason: Option<String>,
    pub current_obligation: Option<f64>,
    pub current_spend: Option<f64>,
    pub spend_ceiling: Option<f64>,
    pub base_value: Option<f64>,
    pub funding_source: Option<String>,
    pub status: String,
    pub pop_start_date: Option<NaiveDate>,
    pub pop_end_date: Option<NaiveDate>,
    pub option_years: Option<i32>,
    pub reporting_frequency: Option<String>,
    pub last_report_date: Option<NaiveDate>,
    pub prime_contractor: Option<String>,
    pub contract_type: Option<String>,
    pub invoice_count: Option<i32>,
    pub classification: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateContract {
    pub number: Option<String>,
    pub name: Option<String>,
    pub awarding_agency: Option<String>,
    pub award_date: Option<NaiveDate>,
    pub start_date: Option<NaiveDate>,
    pub end_date: Option<NaiveDate>,
    pub modification_date: Option<NaiveDate>,
    pub modification_count: Option<i32>,
    pub latest_modification_number: Option<String>,
    pub latest_modification_reason: Option<String>,
    pub current_obligation: Option<f64>,
    pub current_spend: Option<f64>,
    pub spend_ceiling: Option<f64>,
    pub base_value: Option<f64>,
    pub funding_source: Option<String>,
    pub status: Option<String>,
    pub pop_start_date: Option<NaiveDate>,
    pub pop_end_date: Option<NaiveDate>,
    pub option_years: Option<i32>,
    pub reporting_frequency: Option<String>,
    pub last_report_date: Option<NaiveDate>,
    pub prime_contractor: Option<String>,
    pub contract_type: Option<String>,
    pub invoice_count: Option<i32>,
    pub classification: Option<String>,
}

impl UpdateContract {
    pub fn is_empty(&self) -> bool {
        self.number.is_none()
            && self.name.is_none()
            && self.awarding_agency.is_none()
            && self.award_date.is_none()
            && self.start_date.is_none()
            && self.end_date.is_none()
            && self.modification_date.is_none()
            && self.modification_count.is_none()
            && self.latest_modification_number.is_none()
            && self.latest_modification_reason.is_none()
            && self.current_obligation.is_none()
            && self.current_spend.is_none()
            && self.spend_ceiling.is_none()
            && self.base_value.is_none()
            && self.funding_source.is_none()
            && self.status.is_none()
            && self.pop_start_date.is_none()
            && self.pop_end_date.is_none()
            && self.option_years.is_none()
            && self.reporting_frequency.is_none()
            && self.last_report_date.is_none()
            && self.prime_contractor.is_none()
            && self.contract_type.is_none()
            && self.invoice_count.is_none()
            && self.classification.is_none()
    }
}
