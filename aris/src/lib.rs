use std::{
    collections::VecDeque,
    fmt::Debug,
    future::Future,
    hash::Hash,
    io::Read,
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, Result};
use casus::{Event, Waiter};
use dashmap::{mapref::entry::Entry, DashMap, DashSet};
use flate2::{
    read::{ZlibDecoder, ZlibEncoder},
    Compression,
};
use hmac::{Hmac, Mac};
use rand::distributions::DistString;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr as DeserializeRepr, Serialize_repr as SerializeRepr};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

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
        socket.hello().await?;
        socket.clone().start_heartbeat_watchdog().await;
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
                        i.socket.encoder.clone(),
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

#[derive(Debug)]
pub enum Msg {
    Text(String),
    Binary(Vec<u8>),
}

type Encoder = Arc<Mutex<ZlibEncoder<ZlibVec>>>;

#[derive(Debug)]
struct ZlibVec(Vec<u8>);

impl Read for ZlibVec {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        Read::read(&mut &self.0[..], buf)
    }
}

impl From<String> for ZlibVec {
    fn from(v: String) -> Self {
        v.as_bytes().into()
    }
}

impl From<&str> for ZlibVec {
    fn from(v: &str) -> Self {
        v.as_bytes().into()
    }
}

impl From<&[u8]> for ZlibVec {
    fn from(v: &[u8]) -> Self {
        Self(v.to_vec())
    }
}

impl From<Vec<u8>> for ZlibVec {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
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
    encoder: Encoder,
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
            encoder: Arc::new(Mutex::new(ZlibEncoder::new(
                vec![].into(),
                Compression::default(),
            ))),
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
        Self::send_pieces(
            msg,
            self.server.should_compress,
            self.send_adapter.clone(),
            self.encoder.clone(),
        )
        .await
    }

    pub(crate) async fn send_pieces(
        msg: ServerMessage,
        should_compress: bool,
        send_adapter: Arc<E>,
        encoder: Encoder,
    ) -> Result<()> {
        let msg = serde_json::to_string(&msg)?;
        if should_compress {
            send_adapter
                .send(Msg::Binary(Self::compress_pieces(msg, encoder)?))
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

    pub(crate) fn compress_pieces(text: String, encoder: Encoder) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        let mut g = encoder.lock().unwrap();
        g.reset(text.into());
        g.read_to_end(&mut buf)?;
        Ok(buf)
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

    async fn start_heartbeat_watchdog(mut self) {
        S::spawn(async move {
            loop {
                let now = now().unwrap();
                let next_heartbeat = {
                    *self.last_heartbeat.lock().unwrap()
                        + (self.server.heartbeat_interval as u64)
                        + 2
                };
                if now > next_heartbeat {
                    let _ = self
                        .send_adapter
                        .close(4001, Some("Heartbeat timed out"))
                        .await;
                    self.closed(4001, Some("Heartbeat timed out"));
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
    pub fn new(channel: String, socket: Socket<S, E, L>) -> Self {
        Self { channel, socket }
    }
}

#[derive(Clone, Debug)]
pub struct Client<S, E, L>
where
    S: SpawnAdapter + 'static,
    E: ClientSendAdapter + 'static,
    L: SleepAdapter + 'static,
{
    decoder: Arc<Mutex<ZlibDecoder<ZlibVec>>>,
    spawn_adapter: PhantomData<S>,
    send_adapter: Arc<E>,
    sleep_adapter: PhantomData<L>,
    messages: Arc<DashMap<String, Waiter<Option<String>>>>,
    heartbeat_interval: Arc<Mutex<u16>>,
    socket_id: Arc<Mutex<String>>,
    hello_event: Arc<Event>,
    heartbeat_acked: Arc<Mutex<bool>>,
    subscriptions: Arc<DashMap<String, ClientSubscription<S, E, L>>>,
}

impl<S, E, L> Client<S, E, L>
where
    S: SpawnAdapter + 'static,
    E: ClientSendAdapter + 'static,
    L: SleepAdapter + 'static,
{
    pub fn new(_spawn_adapter: S, send_adapter: E, _sleep_adapterr: E) -> Self {
        Self {
            decoder: Arc::new(Mutex::new(ZlibDecoder::new(vec![].into()))),
            spawn_adapter: PhantomData,
            send_adapter: Arc::new(send_adapter),
            sleep_adapter: PhantomData,
            messages: Arc::new(DashMap::new()),
            heartbeat_interval: Arc::new(Mutex::new(60)),
            socket_id: Arc::new(Mutex::new("".into())),
            hello_event: Arc::new(Event::new()),
            heartbeat_acked: Arc::new(Mutex::new(true)),
            subscriptions: Arc::new(DashMap::new()),
        }
    }

    pub async fn handle_message(&self, msg: Msg) -> Result<()> {
        let msg = serde_json::from_str::<ServerMessage>(&match msg {
            Msg::Binary(b) => self.decompress(b)?,
            Msg::Text(t) => t,
        })?;
        match msg.op {
            ServerOpCode::Event => {
                if let Some(ServerMessageData::Event(s)) = msg.data {
                    if let Some(channel) = msg.channel {
                        self.dispatch(channel, s)
                    }
                }
            },
            ServerOpCode::HeartbeatAck => {
                *self.heartbeat_acked.lock().unwrap() = true;
            },
            ServerOpCode::Hello => {
                if let Some(ServerMessageData::Hello {
                    heartbeat_interval,
                    socket_id,
                }) = msg.data
                {
                    *self.heartbeat_interval.lock().unwrap() = heartbeat_interval;
                    *self.socket_id.lock().unwrap() = socket_id;
                    self.hello_event.set();
                }
            },
            ServerOpCode::Reply => {
                if let Some(ServerMessageData::Reply { n, error }) = msg.data {
                    let m = self.messages.remove(&n);
                    if let Some((_, m)) = m {
                        m.wake(error)
                    }
                }
            },
        }
        Ok(())
    }

    fn dispatch(&self, channel: String, event: String) {
        if let Some(sub) = self.subscriptions.get(&channel) {
            sub.push(event);
        }
    }

    pub(crate) fn decompress(&self, bytes: Vec<u8>) -> Result<String> {
        let mut buf = String::new();
        let mut g = self.decoder.lock().unwrap();
        g.reset(bytes.into());
        g.read_to_string(&mut buf)?;
        Ok(buf)
    }

    pub async fn subscribe(
        &self,
        channel: String,
        auth: Option<String>,
    ) -> Result<ClientSubscription<S, E, L>> {
        let entry = self.subscriptions.entry(channel.clone());
        match entry {
            Entry::Occupied(_) => Err(anyhow!("Already subscribed to channel {}", &channel)),
            Entry::Vacant(e) => {
                let nonce = format!("{}-{}", rand_string(16), now()?);
                let waiter = Waiter::new();
                self.messages.insert(nonce.clone(), waiter.clone());
                self.send_adapter
                    .send(serde_json::to_string(&ClientMessage {
                        op: ClientOpCode::Subscribe,
                        nonce,
                        data: Some(ClientMessageData::Subscribe {
                            channel: channel.clone(),
                            auth,
                        }),
                    })?)
                    .await?;
                if let Some(e) = waiter.await {
                    return Err(anyhow!("{}", e));
                }
                let sub = ClientSubscription::new(self.clone(), channel);
                e.insert(sub.clone());
                Ok(sub)
            },
        }
    }
}

#[derive(Clone, Debug)]
pub struct ClientSubscription<S, E, L>
where
    S: SpawnAdapter + 'static,
    E: ClientSendAdapter + 'static,
    L: SleepAdapter + 'static,
{
    client: Client<S, E, L>,
    channel: Arc<String>,
    queue: Arc<Mutex<VecDeque<String>>>,
    waiters: Arc<Mutex<VecDeque<Waiter<Option<String>>>>>,
    finished: Arc<Mutex<bool>>,
}

impl<S, E, L> ClientSubscription<S, E, L>
where
    S: SpawnAdapter + 'static,
    E: ClientSendAdapter + 'static,
    L: SleepAdapter + 'static,
{
    pub fn new(client: Client<S, E, L>, channel: String) -> Self {
        Self {
            client,
            channel: Arc::new(channel),
            queue: Arc::new(Mutex::new(VecDeque::new())),
            waiters: Arc::new(Mutex::new(VecDeque::new())),
            finished: Arc::new(Mutex::new(false)),
        }
    }

    pub async fn next(&self) -> Option<String> {
        if let Some(s) = self.queue.lock().unwrap().pop_front() {
            return Some(s);
        }
        if *self.finished.lock().unwrap() {
            return None;
        }
        let waiter = Waiter::new();
        self.waiters.lock().unwrap().push_back(waiter.clone());
        waiter.await;
        self.queue.lock().unwrap().pop_front()
    }

    pub fn push(&self, v: String) {
        if *self.finished.lock().unwrap() {
            return;
        }
        let mut waiters = self.waiters.lock().unwrap();
        if let Some(waiter) = waiters.pop_front() {
            waiter.wake(Some(v));
        } else {
            self.queue.lock().unwrap().push_back(v);
        }
    }

    pub fn extend(&self, iter: impl Iterator<Item = String>) {
        if *self.finished.lock().unwrap() {
            return;
        }
        for i in iter {
            self.push(i);
        }
    }

    pub async fn unsubscribe(&self) -> Result<()> {
        let entry = self.client.subscriptions.entry((*self.channel).clone());
        match entry {
            Entry::Vacant(_) => Err(anyhow!("Not subscribed to channel {}", &self.channel)),
            Entry::Occupied(e) => {
                let nonce = format!("{}-{}", rand_string(16), now()?);
                let waiter = Waiter::new();
                self.client.messages.insert(nonce.clone(), waiter.clone());
                self.client
                    .send_adapter
                    .send(serde_json::to_string(&ClientMessage {
                        op: ClientOpCode::Unsubscribe,
                        nonce,
                        data: Some(ClientMessageData::Unsubscribe {
                            channel: (*self.channel).clone(),
                        }),
                    })?)
                    .await?;
                if let Some(e) = waiter.await {
                    return Err(anyhow!("{}", e));
                }
                e.remove();
                *self.finished.lock().unwrap() = true;
                for i in self.waiters.lock().unwrap().iter() {
                    i.wake(None);
                }
                Ok(())
            },
        }
    }
}

#[derive(Debug)]
pub struct Publisher<P>
where
    P: PublishAdapter,
{
    secret: String,
    channel_prefix: String,
    publish_adapter: P,
}

impl<P> Publisher<P>
where
    P: PublishAdapter,
{
    pub fn new<S: ToString, C: ToString>(secret: S, channel_prefix: C, publish_adapter: P) -> Self {
        Self {
            secret: secret.to_string(),
            channel_prefix: channel_prefix.to_string(),
            publish_adapter,
        }
    }

    pub async fn publish(&self, event: &str, data: &str) -> Result<()> {
        self.publish_adapter.publish(event, data).await
    }

    pub fn issue_channel(&self) -> Result<String> {
        Ok(format!(
            "{}-{}-{}",
            self.channel_prefix,
            rand_string(16),
            now()?
        ))
    }

    pub fn issue_private_channel(&self) -> Result<String> {
        Ok(format!("private-{}", self.issue_channel()?))
    }

    pub fn authorize_subscription(&self, socket_id: &str, channel: &str) -> Result<String> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(self.secret.as_bytes())?;
        Mac::update(&mut mac, format!("{}:{}", socket_id, channel).as_bytes());
        Ok(hex::encode(&Mac::finalize(mac).into_bytes()[..]))
    }
}

fn now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

fn rand_string(length: usize) -> String {
    rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), length)
}

#[derive(Debug, Deserialize, Serialize)]
struct ClientMessage {
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
enum ClientMessageData {
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
struct ServerMessage {
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
enum ServerMessageData {
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

pub trait SpawnAdapter: Debug + Clone {
    type Handle: SpawnHandle;

    fn spawn(fut: impl Future + Send + 'static) -> Self::Handle;
}

pub trait SpawnHandle: Debug + Future<Output = Result<()>> {
    fn cancel(self);
}

#[async_trait::async_trait]
pub trait SendAdapter: Debug + Clone + Send + Sync {
    async fn send(&self, msg: Msg) -> Result<()>;

    async fn close(&self, code: u16, msg: Option<&str>) -> Result<()>;
}

#[async_trait::async_trait]
pub trait ClientSendAdapter: Debug + Clone + Send + Sync {
    async fn send(&self, msg: String) -> Result<()>;

    async fn close(&self, code: u16, msg: Option<&str>) -> Result<()>;
}

#[async_trait::async_trait]
pub trait PublishAdapter: Debug + Clone + Send + Sync {
    async fn publish(&self, event: &str, msg: &str) -> Result<()>;
}

#[async_trait::async_trait]
pub trait SleepAdapter: Debug + Clone + Send + Sync {
    async fn sleep(secs: u64);
}
