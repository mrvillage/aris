use std::{
    hash::Hash,
    io::Write,
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, Result};
use dashmap::{mapref::entry::Entry, DashMap, DashSet};
use flate2::{write::ZlibEncoder, Compression};
use hmac::Mac;

use crate::{
    message::{
        ClientMessage, ClientMessageData, ClientOpCode, Msg, ServerMessage, ServerMessageData,
        ServerOpCode,
    },
    traits::{SendAdapter, SleepAdapter, SpawnAdapter},
    utils::{now, rand_string},
    HmacSha256,
};

#[derive(Clone, Debug)]
pub struct Server<S, E, L>
where
    S: SpawnAdapter + 'static,
    E: SendAdapter + 'static,
    L: SleepAdapter + 'static,
{
    pub(crate) sockets: Arc<DashMap<String, Socket<S, E, L>>>,
    #[allow(clippy::type_complexity)]
    subscriptions: Arc<DashMap<String, DashSet<ServerSubscription<S, E, L>>>>,
    pub(crate) secret: Arc<String>,
    pub(crate) heartbeat_interval: u16,
    pub(crate) should_compress: bool,
}

impl<S, E, L> Server<S, E, L>
where
    S: SpawnAdapter + 'static,
    E: SendAdapter + 'static,
    L: SleepAdapter + 'static,
{
    #[inline]
    pub fn new(
        spawn_adapter: S,
        sleep_adapter: L,
        secret: String,
        heartbeat_interval: u16,
    ) -> Self {
        Self::inner_new(
            spawn_adapter,
            sleep_adapter,
            secret,
            heartbeat_interval,
            true,
        )
    }

    #[inline]
    fn inner_new(
        _spawn_adapter: S,
        _sleep_adapter: L,
        secret: String,
        heartbeat_interval: u16,
        should_compress: bool,
    ) -> Self {
        Self {
            sockets: Arc::new(DashMap::new()),
            subscriptions: Arc::new(DashMap::new()),
            heartbeat_interval,
            secret: Arc::new(secret),
            should_compress,
        }
    }

    #[inline]
    pub fn without_compression(
        spawn_adapter: S,
        sleep_adapter: L,
        secret: String,
        heartbeat_interval: u16,
    ) -> Self {
        Self::inner_new(
            spawn_adapter,
            sleep_adapter,
            secret,
            heartbeat_interval,
            false,
        )
    }

    #[inline]
    pub async fn connect(&self, send: E) -> Result<Socket<S, E, L>> {
        let socket = Socket::new(self.clone(), send)?;
        self.sockets.insert((*socket.id).clone(), socket.clone());
        println!("sending hello");
        socket.hello().await?;
        println!("hello sent");
        socket.clone().start_heartbeat_watchdog();
        Ok(socket)
    }

    pub async fn publish(&self, channel: &str, data: &str) -> Result<()> {
        let subscriptions = self.subscriptions.get(channel);
        if let Some(subscriptions) = subscriptions {
            let futures: Vec<_> = subscriptions
                .value()
                .iter()
                .map(|i| {
                    let msg = ServerMessage {
                        op: ServerOpCode::Event,
                        channel: Some(channel.to_string()),
                        data: Some(ServerMessageData::Event(data.to_string())),
                    };
                    S::spawn(Socket::<S, E, L>::send_pieces(
                        msg,
                        self.should_compress,
                        i.socket.send_adapter.clone(),
                    ))
                })
                .collect();
            for i in futures {
                i.await?;
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Socket<S, E, L>
where
    S: SpawnAdapter + 'static,
    E: SendAdapter + 'static,
    L: SleepAdapter + 'static,
{
    id: Arc<String>,
    server: Server<S, E, L>,
    subscriptions: Arc<DashMap<String, ServerSubscription<S, E, L>>>,
    send_adapter: Arc<E>,
    last_heartbeat: Arc<Mutex<u64>>,
    is_closed: Arc<Mutex<bool>>,
}

impl<S, E, L> Socket<S, E, L>
where
    S: SpawnAdapter + 'static,
    E: SendAdapter + 'static,
    L: SleepAdapter + 'static,
{
    pub(crate) fn new(server: Server<S, E, L>, send_adapter: E) -> Result<Self> {
        Ok(Socket {
            id: Arc::new(rand_string(16)),
            server,
            subscriptions: Arc::new(DashMap::new()),
            send_adapter: Arc::new(send_adapter),
            last_heartbeat: Arc::new(Mutex::new(now()?)),
            is_closed: Arc::new(Mutex::new(false)),
        })
    }

    pub fn closed(&mut self, _code: u16, _reason: Option<&str>) {
        self.server.sockets.remove(self.id.as_str());
        *self.is_closed.lock().unwrap() = true;
    }

    pub async fn handle_message(&self, message: &str) -> Result<()> {
        if *self.is_closed.lock().unwrap() {
            return Err(anyhow!("Socket is closed"));
        }
        let message = serde_json::from_str::<ClientMessage>(message)?;
        let nonce = message.nonce.clone();
        let res = self.handle_message_inner(message).await;
        match &res {
            Ok(_) => {},
            Err(_) => self.reply_error(&nonce, "Unknown fatal error").await?,
        };
        res
    }

    async fn handle_message_inner(&self, message: ClientMessage) -> Result<()> {
        match message.op {
            ClientOpCode::Heartbeat => {
                *self.last_heartbeat.lock().unwrap() = now()?;
                self.send(ServerMessage {
                    op: ServerOpCode::HeartbeatAck,
                    channel: None,
                    data: None,
                })
                .await
            },
            ClientOpCode::Subscribe => match message.data {
                Some(d) => match d {
                    ClientMessageData::Subscribe { channel, auth } => {
                        self.subscribe(&message.nonce, channel, auth).await
                    },
                    _ => {
                        self.reply_error(&message.nonce, "Incorrect data field")
                            .await
                    },
                },
                None => self.reply_error(&message.nonce, "Missing data field").await,
            },
            ClientOpCode::Unsubscribe => match message.data {
                Some(d) => match d {
                    ClientMessageData::Unsubscribe { channel } => {
                        self.unsubscribe(&message.nonce, channel).await
                    },
                    _ => Err(anyhow!("Incorrect data field")),
                },
                None => Err(anyhow!("Missing data field")),
            },
        }
    }

    pub(crate) async fn send(&self, msg: ServerMessage) -> Result<()> {
        Self::send_pieces(msg, self.server.should_compress, self.send_adapter.clone()).await
    }

    pub(crate) async fn send_pieces(
        msg: ServerMessage,
        should_compress: bool,
        send_adapter: Arc<E>,
    ) -> Result<()> {
        let msg = serde_json::to_string(&msg)?;
        if should_compress {
            send_adapter
                .send(Msg::Binary(Self::compress_pieces(msg)?))
                .await
        } else {
            send_adapter.send(Msg::Text(msg)).await
        }
    }

    async fn reply_error(&self, n: &str, e: &str) -> Result<()> {
        self.send(ServerMessage {
            op: ServerOpCode::Reply,
            channel: None,
            data: Some(ServerMessageData::Reply {
                n: n.into(),
                error: Some(e.into()),
            }),
        })
        .await?;
        Ok(())
    }

    pub(crate) fn compress_pieces(text: String) -> Result<Vec<u8>> {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(text.as_bytes())?;
        Ok(e.finish()?)
    }

    pub(crate) async fn hello(&self) -> Result<()> {
        let msg = ServerMessage {
            op: ServerOpCode::Hello,
            channel: None,
            data: Some(ServerMessageData::Hello {
                heartbeat_interval: self.server.heartbeat_interval,
                socket_id: self.id.to_string(),
            }),
        };
        self.send(msg).await?;
        Ok(())
    }

    async fn subscribe(&self, n: &str, channel: String, auth: Option<String>) -> Result<()> {
        let entry = self.subscriptions.entry(channel.clone());
        if let Entry::Occupied(_) = entry {
            return self
                .reply_error(n, &format!("Already subscribed to {}", &channel))
                .await;
        };
        if channel.starts_with("private-") {
            match auth {
                None => return Err(anyhow!("No auth provided for a private channel")),
                Some(auth) => {
                    if self.verify_auth(&channel, &auth).is_err() {
                        return Err(anyhow!("Unauthorized"));
                    }
                },
            }
        }
        entry.or_insert(ServerSubscription::new(channel.clone(), self.clone()));
        self.server
            .subscriptions
            .entry(channel.clone())
            .and_modify(|s| {
                s.insert(ServerSubscription::new(channel.clone(), self.clone()));
            })
            .or_insert_with(|| {
                let set = DashSet::with_capacity(1);
                set.insert(ServerSubscription::new(channel.clone(), self.clone()));
                set
            });
        self.send(ServerMessage {
            op: ServerOpCode::Reply,
            channel: None,
            data: Some(ServerMessageData::Reply {
                n: n.into(),
                error: None,
            }),
        })
        .await?;
        Ok(())
    }

    fn verify_auth(&self, channel: &str, auth: &str) -> Result<()> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(self.server.secret.as_bytes())?;
        Mac::update(&mut mac, format!("{}:{}", self.id, channel).as_bytes());
        mac.verify_slice(&hex::decode(auth)?).map_err(|e| e.into())
    }

    async fn unsubscribe(&self, n: &str, channel: String) -> Result<()> {
        let v = self.subscriptions.remove(&channel);
        match v {
            Some((_, v)) => {
                self.server
                    .subscriptions
                    .entry(channel.clone())
                    .and_modify(|i| {
                        i.remove(&v);
                    });
                self.server
                    .subscriptions
                    .remove_if(&channel, |_, v| v.is_empty());
                self.send(ServerMessage {
                    op: ServerOpCode::Reply,
                    channel: None,
                    data: Some(ServerMessageData::Reply {
                        n: n.into(),
                        error: None,
                    }),
                })
                .await
            },
            None => {
                self.reply_error(n, &format!("Not subscribed to channel {}", &channel))
                    .await
            },
        }
    }

    fn start_heartbeat_watchdog(mut self) {
        S::spawn(async move {
            loop {
                let now = now().unwrap();
                let next_heartbeat = {
                    *self.last_heartbeat.lock().unwrap()
                        + (self.server.heartbeat_interval as u64)
                        + 2
                };
                if now >= next_heartbeat {
                    let _ = self
                        .send_adapter
                        .close(4001, Some("Heartbeat timed out"))
                        .await;
                    self.closed(4001, Some("Heartbeat timed out"));
                } else {
                    L::sleep(next_heartbeat - now).await;
                }
            }
        });
    }
}

impl<S, E, L> Drop for Socket<S, E, L>
where
    S: SpawnAdapter + 'static,
    E: SendAdapter + 'static,
    L: SleepAdapter + 'static,
{
    fn drop(&mut self) {
        self.closed(0, None);
        for i in self.subscriptions.iter() {
            let (k, v) = i.pair();
            self.server
                .subscriptions
                .entry(k.to_string())
                .and_modify(|i| {
                    i.remove(v);
                });
            self.server.subscriptions.remove_if(k, |_, v| v.is_empty());
        }
    }
}

impl<S, E, L> std::fmt::Debug for Socket<S, E, L>
where
    S: SpawnAdapter + 'static,
    E: SendAdapter + 'static,
    L: SleepAdapter + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socket")
            .field("id", &self.id)
            .field("server", &self.server)
            .field("subscriptions", &self.subscriptions)
            .finish()
    }
}

#[derive(Debug)]
struct ServerSubscription<S, E, L>
where
    S: SpawnAdapter + 'static,
    E: SendAdapter + 'static,
    L: SleepAdapter + 'static,
{
    channel: String,
    socket: Socket<S, E, L>,
}

impl<S, E, L> PartialEq for ServerSubscription<S, E, L>
where
    S: SpawnAdapter + 'static,
    E: SendAdapter + 'static,
    L: SleepAdapter + 'static,
{
    fn eq(&self, other: &Self) -> bool {
        self.channel == other.channel && self.socket.id == other.socket.id
    }
}

impl<S, E, L> Eq for ServerSubscription<S, E, L>
where
    S: SpawnAdapter + 'static,
    E: SendAdapter + 'static,
    L: SleepAdapter + 'static,
{
}

impl<S, E, L> Hash for ServerSubscription<S, E, L>
where
    S: SpawnAdapter + 'static,
    E: SendAdapter + 'static,
    L: SleepAdapter + 'static,
{
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.channel.hash(state);
        self.socket.id.hash(state);
    }
}

impl<S, E, L> ServerSubscription<S, E, L>
where
    S: SpawnAdapter + 'static,
    E: SendAdapter + 'static,
    L: SleepAdapter + 'static,
{
    pub(crate) fn new(channel: String, socket: Socket<S, E, L>) -> Self {
        Self { channel, socket }
    }
}
