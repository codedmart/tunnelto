use crate::auth::reconnect_token::ReconnectTokenPayload;
use crate::{ReconnectToken, CONFIG};
use futures::{SinkExt, StreamExt};
use log::error;
use tunnelto_lib::{ClientHello, ClientId, ClientType, ServerHello};
use warp::filters::ws::{Message, WebSocket};

pub struct ClientHandshake {
    pub id: ClientId,
    pub sub_domain: String,
    pub is_anonymous: bool,
}

pub async fn auth_client_handshake(
    mut websocket: WebSocket,
) -> Option<(WebSocket, ClientHandshake)> {
    let client_hello_data = match websocket.next().await {
        Some(Ok(msg)) => msg,
        _ => {
            error!("no client init message");
            return None;
        }
    };

    auth_client(client_hello_data.as_bytes(), websocket).await
}

async fn auth_client(
    client_hello_data: &[u8],
    mut websocket: WebSocket,
) -> Option<(WebSocket, ClientHandshake)> {
    // parse the client hello
    let client_hello: ClientHello = match serde_json::from_slice(client_hello_data) {
        Ok(ch) => ch,
        Err(e) => {
            error!("invalid client hello: {}", e);
            let data = serde_json::to_vec(&ServerHello::AuthFailed).unwrap_or_default();
            let _ = websocket.send(Message::binary(data)).await;
            return None;
        }
    };

    let (_auth_key, client_id, requested_sub_domain) = match client_hello.client_type {
        ClientType::Anonymous => {
            error!("anonymous users not allowed");
            return None;
        }
        ClientType::Auth { key } => {
            // Check auth
            match crate::AUTH_DB_SERVICE
                .get_account_id_for_auth_key(&key.0)
                .await
            {
                Err(_) => {
                    error!("anonymous users not allowed");
                    return None;
                }
                Ok(_) => match client_hello.sub_domain {
                    Some(requested_sub_domain) => {
                        let client_id = key.client_id();
                        let (ws, sub_domain) = match sanitize_sub_domain_and_pre_validate(
                            websocket,
                            requested_sub_domain,
                            &client_id,
                        )
                        .await
                        {
                            Some(s) => s,
                            None => return None,
                        };
                        websocket = ws;

                        (key, client_id, sub_domain)
                    }
                    None => {
                        return if let Some(token) = client_hello.reconnect_token {
                            handle_reconnect_token(token, websocket).await
                        } else {
                            let sub_domain = ServerHello::random_domain();
                            Some((
                                websocket,
                                ClientHandshake {
                                    id: ClientId::generate(),
                                    sub_domain,
                                    is_anonymous: true,
                                },
                            ))
                        }
                    }
                },
            }
        }
    };

    Some((
        websocket,
        ClientHandshake {
            id: client_id,
            sub_domain: requested_sub_domain,
            is_anonymous: false,
        },
    ))
}

async fn handle_reconnect_token(
    token: ReconnectToken,
    mut websocket: WebSocket,
) -> Option<(WebSocket, ClientHandshake)> {
    let payload = match ReconnectTokenPayload::verify(token, &CONFIG.master_sig_key) {
        Ok(payload) => payload,
        Err(e) => {
            error!("invalid reconnect token: {:?}", e);
            let data = serde_json::to_vec(&ServerHello::AuthFailed).unwrap_or_default();
            let _ = websocket.send(Message::binary(data)).await;
            return None;
        }
    };

    log::debug!(
        "accepting reconnect token from client: {}",
        &payload.client_id
    );

    Some((
        websocket,
        ClientHandshake {
            id: payload.client_id,
            sub_domain: payload.sub_domain,
            is_anonymous: true,
        },
    ))
}

async fn sanitize_sub_domain_and_pre_validate(
    mut websocket: WebSocket,
    requested_sub_domain: String,
    client_id: &ClientId,
) -> Option<(WebSocket, String)> {
    // ignore uppercase
    let sub_domain = requested_sub_domain.to_lowercase();

    if sub_domain
        .chars()
        .filter(|c| !(c.is_alphanumeric() || c == &'-'))
        .count()
        > 0
    {
        error!("invalid client hello: only alphanumeric/hyphen chars allowed!");
        let data = serde_json::to_vec(&ServerHello::InvalidSubDomain).unwrap_or_default();
        let _ = websocket.send(Message::binary(data)).await;
        return None;
    }

    // ensure it's not a restricted one
    if CONFIG.blocked_sub_domains.contains(&sub_domain) {
        error!("invalid client hello: sub-domain restrict!");
        let data = serde_json::to_vec(&ServerHello::SubDomainInUse).unwrap_or_default();
        let _ = websocket.send(Message::binary(data)).await;
        return None;
    }

    // ensure this sub-domain isn't taken
    // check all instances
    match crate::network::instance_for_host(&sub_domain).await {
        Err(crate::network::Error::DoesNotServeHost) => {}
        Ok((_, existing_client)) => {
            if &existing_client != client_id {
                error!("invalid client hello: requested sub domain in use already!");
                let data = serde_json::to_vec(&ServerHello::SubDomainInUse).unwrap_or_default();
                let _ = websocket.send(Message::binary(data)).await;
                return None;
            }
        }
        Err(e) => {
            log::debug!("Got error checking instances: {:?}", e);
        }
    }

    Some((websocket, sub_domain))
}
