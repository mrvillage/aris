use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr as DeserializeRepr, Serialize_repr as SerializeRepr};

#[derive(Debug)]
pub enum Msg {
    Text(String),
    Binary(Vec<u8>),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ClientMessage {
    // unique nonce to identify the message for a reply
    #[serde(rename = "n")]
    pub nonce: String,
    // op code
    #[serde(rename = "o")]
    pub op: ClientOpCode,
    // data, if any
    #[serde(rename = "d")]
    pub data: Option<ClientMessageData>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ClientMessageData {
    Subscribe {
        channel: String,
        auth: Option<String>,
    },
    Unsubscribe {
        channel: String,
    },
}

#[derive(Debug, DeserializeRepr, SerializeRepr)]
#[repr(u8)]
pub enum ClientOpCode {
    Heartbeat = 0,
    Subscribe = 3,
    Unsubscribe = 4,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ServerMessage {
    // op code
    #[serde(rename = "o")]
    pub op: ServerOpCode,
    // channel
    #[serde(rename = "c")]
    pub channel: Option<String>,
    // data, if any
    #[serde(rename = "d")]
    pub data: Option<ServerMessageData>,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ServerMessageData {
    Event(String),
    Hello {
        heartbeat_interval: u16,
        socket_id: String,
    },
    Reply {
        n: String,
        error: Option<String>,
    },
}

#[derive(Debug, DeserializeRepr, SerializeRepr)]
#[repr(u8)]
pub enum ServerOpCode {
    Event = 0,
    HeartbeatAck = 1,
    Hello = 2,
    Reply = 5,
}
