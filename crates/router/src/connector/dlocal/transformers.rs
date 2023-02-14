use common_utils::pii::{self, Email};
use error_stack::{IntoReport, ResultExt};
use masking::Secret;
use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::{
    core::errors,
    services,
    types::{self, api, storage::enums},
};

#[derive(Debug, Default, Eq, PartialEq, Serialize)]
pub struct Payer {
    pub name: Secret<String>,
    pub email: Secret<String, Email>,
    pub document: String,
}

#[derive(Debug, Default, Eq, Clone, PartialEq, Serialize, Deserialize)]
pub struct Card {
    pub holder_name: Secret<String>,
    pub number: Secret<String, pii::CardNumber>,
    pub cvv: Secret<String>,
    pub expiration_month: Secret<String>,
    pub expiration_year: Secret<String>,
    pub capture: String,
    pub installments_id: Option<String>,
    pub installments: Option<String>,
}

#[derive(Debug, Default, Eq, PartialEq, Serialize)]
pub struct ThreeDSecureReqData {
    pub force: bool,
}

#[derive(Default, Debug, Serialize, Eq, PartialEq)]
pub struct DlocalPaymentsRequest {
    pub amount: i64, //amount in cents, hence passed as integer
    pub currency: enums::Currency,
    pub country: Option<String>,
    pub payment_method_id: String,
    pub payment_method_flow: String,
    pub payer: Payer,
    pub card: Option<Card>,
    pub order_id: String,
    pub notification_url: String,
    pub three_dsecure: Option<ThreeDSecureReqData>,
    pub callback_url: Option<String>,
}

impl TryFrom<&types::PaymentsAuthorizeRouterData> for DlocalPaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::PaymentsAuthorizeRouterData) -> Result<Self, Self::Error> {
        let email = item
            .request
            .email
            .as_ref()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "email_id",
            })?
            .clone();
        match item.request.payment_method_data {
            api::PaymentMethod::Card(ref ccard) => {
                let should_capture = matches!(
                    item.request.capture_method,
                    Some(enums::CaptureMethod::Automatic)
                );
                let payment_request = Self {
                    amount: item.request.amount,
                    country: Some(get_currency(item.request.currency)),
                    currency: item.request.currency,
                    payment_method_id: "CARD".to_string(),
                    payment_method_flow: "DIRECT".to_string(),
                    payer: Payer {
                        name: ccard.card_holder_name.clone(),
                        email,
                        //todo: this needs to be customer unique identifier like PAN, CPF, etc
                        // we need to mandatorily receive this from merchant and pass
                        // so, we need to get this data from payment_core and pass
                        // [#589]: Allow securely collecting PII from customer in payments request
                        document: "36691251830".to_string(),
                    },
                    card: Some(Card {
                        holder_name: ccard.card_holder_name.clone(),
                        number: ccard.card_number.clone(),
                        cvv: ccard.card_cvc.clone(),
                        expiration_month: ccard.card_exp_month.clone(),
                        expiration_year: ccard.card_exp_year.clone(),
                        capture: should_capture.to_string(),
                        installments_id: item
                            .request
                            .mandate_id
                            .as_ref()
                            .map(|ids| ids.mandate_id.clone()),
                        installments: item.request.mandate_id.clone().map(|_| "1".to_string()),
                    }),
                    order_id: item.payment_id.clone(),
                    notification_url: match &item.return_url {
                        Some(val) => val.to_string(),
                        None => "http://wwww.sandbox.juspay.in/hackathon/H1005".to_string(),
                    },
                    three_dsecure: None, // Ideally item.auth_type should have nonThreeDS which is not happening
                    // three_dsecure : match item.auth_type {
                    //     ThreeDs => Some(ThreeDSecureReqData { force: (true) }),
                    //     NoThreeDs => None,
                    // },
                    // wallet: None,
                    callback_url: item.return_url.clone(),
                };
                Ok(payment_request)
            }
            api::PaymentMethod::Wallet(ref _wallet) => {
                let payment_request = Self {
                    amount: item.request.amount,
                    country: Some(get_currency(item.request.currency)),
                    currency: item.request.currency,
                    payment_method_id: "MP".to_string(),
                    payment_method_flow: "REDIRECT".to_string(),
                    payer: Payer {
                        name: "dummyEmail@gmail.com".to_string().into(),
                        email,
                        document: "36691251830".to_string(),
                    },
                    card: None,
                    order_id: item.payment_id.clone(),
                    notification_url: match &item.return_url {
                        Some(val) => val.to_string(),
                        None => "http://wwww.sandbox.juspay.in/hackathon/H1005".to_string(),
                    },
                    // wallet:None,
                    three_dsecure: None,
                    callback_url: item.return_url.clone(),
                };
                Ok(payment_request)
            }
            _ => Err(
                errors::ConnectorError::NotImplemented("Current Payment Method".to_string()).into(),
            ),
        }
    }
}

fn get_currency(item: enums::Currency) -> String {
    match item {
        storage_models::enums::Currency::BRL => "BR".to_string(),
        _ => "IN".to_string(),
    }
}

pub struct DlocalPaymentsSyncRequest {
    pub authz_id: String,
}

impl TryFrom<&types::PaymentsSyncRouterData> for DlocalPaymentsSyncRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::PaymentsSyncRouterData) -> Result<Self, Self::Error> {
        Ok(Self {
            authz_id: (item
                .request
                .connector_transaction_id
                .get_connector_transaction_id()
                .change_context(errors::ConnectorError::MissingConnectorTransactionID)?),
        })
    }
}

pub struct DlocalPaymentsCancelRequest {
    pub cancel_id: String,
}

impl TryFrom<&types::PaymentsCancelRouterData> for DlocalPaymentsCancelRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::PaymentsCancelRouterData) -> Result<Self, Self::Error> {
        Ok(Self {
            cancel_id: (item.request.connector_transaction_id.clone()),
        })
    }
}

#[derive(Default, Debug, Serialize, Eq, PartialEq)]
pub struct DlocalPaymentsCaptureRequest {
    pub authorization_id: String,
    pub amount: i64,
    pub currency: String,
    pub order_id: String,
}

impl TryFrom<&types::PaymentsCaptureRouterData> for DlocalPaymentsCaptureRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::PaymentsCaptureRouterData) -> Result<Self, Self::Error> {
        let amount_to_capture = match item.request.amount_to_capture {
            Some(val) => val,
            None => item.request.amount,
        };
        Ok(Self {
            authorization_id: item.request.connector_transaction_id.clone(),
            amount: amount_to_capture,
            currency: item.request.currency.to_string(),
            order_id: item.payment_id.clone(),
        })
    }
}
// Auth Struct
pub struct DlocalAuthType {
    pub(super) x_login: String,
    pub(super) x_trans_key: String,
    pub(super) secret: String,
}

impl TryFrom<&types::ConnectorAuthType> for DlocalAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &types::ConnectorAuthType) -> Result<Self, Self::Error> {
        if let types::ConnectorAuthType::SignatureKey {
            api_key,
            key1,
            api_secret,
        } = auth_type
        {
            Ok(Self {
                x_login: (api_key.to_string()),
                x_trans_key: (key1.to_string()),
                secret: (api_secret.to_string()),
            })
        } else {
            Err(errors::ConnectorError::FailedToObtainAuthType.into())
        }
    }
}
#[derive(Debug, Clone, Eq, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum DlocalPaymentStatus {
    Authorized,
    Paid,
    Verified,
    Cancelled,
    #[default]
    Pending,
    Rejected,
}

impl From<DlocalPaymentStatus> for enums::AttemptStatus {
    fn from(item: DlocalPaymentStatus) -> Self {
        match item {
            DlocalPaymentStatus::Authorized => Self::Authorized,
            DlocalPaymentStatus::Verified => Self::Authorized,
            DlocalPaymentStatus::Paid => Self::Charged,
            DlocalPaymentStatus::Pending => Self::AuthenticationPending,
            DlocalPaymentStatus::Cancelled => Self::Voided,
            DlocalPaymentStatus::Rejected => Self::AuthenticationFailed,
        }
    }
}

#[derive(Default, Eq, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThreeDSecureResData {
    pub redirect_url: Option<String>,
}

#[derive(Debug, Default, Eq, Clone, PartialEq, Serialize, Deserialize)]
pub struct DlocalPaymentsResponse {
    status: DlocalPaymentStatus,
    id: String,
    three_dsecure: Option<ThreeDSecureResData>,
}

impl<F, T>
    TryFrom<types::ResponseRouterData<F, DlocalPaymentsResponse, T, types::PaymentsResponseData>>
    for types::RouterData<F, T, types::PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: types::ResponseRouterData<F, DlocalPaymentsResponse, T, types::PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let three_ds_data = match item.response.three_dsecure {
            Some(val) => match val.redirect_url {
                Some(redirect_url) => {
                    let redirection_url_response = Url::parse(&redirect_url)
                        .into_report()
                        .change_context(errors::ConnectorError::ResponseHandlingFailed)
                        .attach_printable("Failed to parse redirection url")?;
                    let form_field_for_redirection = std::collections::HashMap::from_iter(
                        redirection_url_response
                            .query_pairs()
                            .map(|(k, v)| (k.to_string(), v.to_string())),
                    );
                    Some(services::RedirectForm {
                        url: redirect_url,
                        method: services::Method::Get,
                        form_fields: form_field_for_redirection,
                    })
                }
                None => None,
            },
            None => None,
        };

        let response = types::PaymentsResponseData::TransactionResponse {
            resource_id: types::ResponseId::ConnectorTransactionId(item.response.id),
            redirection_data: three_ds_data.clone(),
            redirect: three_ds_data.is_some(),
            mandate_reference: None,
            connector_metadata: None,
        };
        Ok(Self {
            status: enums::AttemptStatus::from(item.response.status),
            response: Ok(response),
            ..item.data
        })
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DlocalPaymentsSyncResponse {
    status: DlocalPaymentStatus,
    id: String,
}

impl<F, T>
    TryFrom<
        types::ResponseRouterData<F, DlocalPaymentsSyncResponse, T, types::PaymentsResponseData>,
    > for types::RouterData<F, T, types::PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: types::ResponseRouterData<
            F,
            DlocalPaymentsSyncResponse,
            T,
            types::PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            status: enums::AttemptStatus::from(item.response.status),
            response: Ok(types::PaymentsResponseData::TransactionResponse {
                resource_id: types::ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: None,
                redirect: false,
                mandate_reference: None,
                connector_metadata: None,
            }),
            ..item.data
        })
    }
}
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DlocalPaymentsCaptureResponse {
    status: DlocalPaymentStatus,
    id: String,
}
impl<F, T>
    TryFrom<
        types::ResponseRouterData<F, DlocalPaymentsCaptureResponse, T, types::PaymentsResponseData>,
    > for types::RouterData<F, T, types::PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: types::ResponseRouterData<
            F,
            DlocalPaymentsCaptureResponse,
            T,
            types::PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            status: enums::AttemptStatus::from(item.response.status),
            response: Ok(types::PaymentsResponseData::TransactionResponse {
                resource_id: types::ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: None,
                redirect: false,
                mandate_reference: None,
                connector_metadata: None,
            }),
            ..item.data
        })
    }
}

pub struct DlocalPaymentsCancelResponse {
    status: DlocalPaymentStatus,
    id: String,
}
impl<F, T>
    TryFrom<
        types::ResponseRouterData<F, DlocalPaymentsCancelResponse, T, types::PaymentsResponseData>,
    > for types::RouterData<F, T, types::PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: types::ResponseRouterData<
            F,
            DlocalPaymentsCancelResponse,
            T,
            types::PaymentsResponseData,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            status: enums::AttemptStatus::from(item.response.status),
            response: Ok(types::PaymentsResponseData::TransactionResponse {
                resource_id: types::ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: None,
                redirect: false,
                mandate_reference: None,
                connector_metadata: None,
            }),
            ..item.data
        })
    }
}

// REFUND :
// Type definition for RefundRequest
#[derive(Default, Debug, Serialize)]
pub struct RefundRequest {
    pub amount: String,
    pub payment_id: String,
    pub currency: String,
    pub notification_url: String,
    pub id: String,
}

impl<F> TryFrom<&types::RefundsRouterData<F>> for RefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::RefundsRouterData<F>) -> Result<Self, Self::Error> {
        let amount_to_refund = item.request.refund_amount.to_string();
        let return_url = match item.return_url.clone() {
            Some(val) => val,
            None => "https://google.com".to_string(),
        };
        let payment_intent = item.request.connector_transaction_id.clone();
        Ok(Self {
            amount: amount_to_refund,
            payment_id: payment_intent,
            currency: (item.request.currency.to_string()),
            id: item.request.refund_id.clone(),
            notification_url: return_url,
        })
    }
}

// Type definition for Refund Response

#[allow(dead_code)]
#[derive(Debug, Serialize, Default, Deserialize, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub enum RefundStatus {
    Success,
    #[default]
    Pending,
    Rejected,
    Cancelled,
}

impl From<RefundStatus> for enums::RefundStatus {
    fn from(item: RefundStatus) -> Self {
        match item {
            RefundStatus::Success => Self::Success,
            RefundStatus::Pending => Self::Pending,
            RefundStatus::Rejected => Self::ManualReview,
            RefundStatus::Cancelled => Self::Failure,
        }
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RefundResponse {
    pub id: String,
    pub status: RefundStatus,
}

impl TryFrom<types::RefundsResponseRouterData<api::Execute, RefundResponse>>
    for types::RefundsRouterData<api::Execute>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: types::RefundsResponseRouterData<api::Execute, RefundResponse>,
    ) -> Result<Self, Self::Error> {
        let refund_status = enums::RefundStatus::from(item.response.status);
        Ok(Self {
            response: Ok(types::RefundsResponseData {
                connector_refund_id: item.response.id,
                refund_status,
            }),
            ..item.data
        })
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct DlocalRefundsSyncRequest {
    pub refund_id: String,
}

impl TryFrom<&types::RefundSyncRouterData> for DlocalRefundsSyncRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &types::RefundSyncRouterData) -> Result<Self, Self::Error> {
        let refund_id = match item.request.connector_refund_id.clone() {
            Some(val) => val,
            None => item.request.refund_id.clone(),
        };
        Ok(Self {
            refund_id: (refund_id),
        })
    }
}
impl TryFrom<types::RefundsResponseRouterData<api::RSync, RefundResponse>>
    for types::RefundsRouterData<api::RSync>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: types::RefundsResponseRouterData<api::RSync, RefundResponse>,
    ) -> Result<Self, Self::Error> {
        let refund_status = enums::RefundStatus::from(item.response.status);
        Ok(Self {
            response: Ok(types::RefundsResponseData {
                connector_refund_id: item.response.id,
                refund_status,
            }),
            ..item.data
        })
    }
}

#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct DlocalErrorResponse {
    pub code: i32,
    pub message: String,
    pub param: Option<String>,
}
