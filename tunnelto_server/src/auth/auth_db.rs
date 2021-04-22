use rusoto_core::{Client, HttpClient, Region};
use rusoto_dynamodb::{AttributeValue, DynamoDb, DynamoDbClient, GetItemError, GetItemInput};

use rusoto_credential::EnvironmentProvider;
use sha2::Digest;
use std::collections::HashMap;
use std::str::FromStr;
use thiserror::Error;
use uuid::Uuid;

pub struct AuthDbService {
    client: DynamoDbClient,
}

impl AuthDbService {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let provider = EnvironmentProvider::default();
        let http_client = HttpClient::new()?;
        let client = Client::new_with(provider, http_client);

        Ok(Self {
            client: DynamoDbClient::new_with_client(
                client,
                Region::Custom {
                    name: "local".to_owned(),
                    endpoint: "http://localhost:8000".to_owned(),
                },
            ),
        })
    }
}

mod key_db {
    pub const TABLE_NAME: &'static str = "tunnelto_auth";
    pub const PRIMARY_KEY: &'static str = "auth_key_hash";
    pub const ACCOUNT_ID: &'static str = "account_id";
}

fn key_id(auth_key: &str) -> String {
    let hash = sha2::Sha256::digest(auth_key.as_bytes()).to_vec();
    base64::encode_config(&hash, base64::URL_SAFE_NO_PAD)
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to get domain item")]
    AuthDbGetItem(#[from] rusoto_core::RusotoError<GetItemError>),

    #[error("The authentication key is invalid")]
    AccountNotFound,

    #[error("The authentication key is invalid")]
    InvalidAccountId(#[from] uuid::Error),

    #[error("The subdomain is not authorized")]
    SubdomainNotAuthorized,
}

pub enum AuthResult {
    ReservedByYou,
    ReservedByOther,
    Available,
}
impl AuthDbService {
    pub async fn get_account_id_for_auth_key(&self, auth_key: &str) -> Result<Uuid, Error> {
        let auth_key_hash = key_id(auth_key);

        let mut input = GetItemInput {
            table_name: key_db::TABLE_NAME.to_string(),
            ..Default::default()
        };
        input.key = {
            let mut item = HashMap::new();
            item.insert(
                key_db::PRIMARY_KEY.to_string(),
                AttributeValue {
                    s: Some(auth_key_hash),
                    ..Default::default()
                },
            );
            item
        };

        let result = self.client.get_item(input).await?;
        let account_str = result
            .item
            .unwrap_or(HashMap::new())
            .get(key_db::ACCOUNT_ID)
            .cloned()
            .unwrap_or(AttributeValue::default())
            .s
            .ok_or(Error::AccountNotFound)?;

        let uuid = Uuid::from_str(&account_str)?;
        Ok(uuid)
    }
}
