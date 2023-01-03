use std::{
    collections::VecDeque,
    io::Read,
    marker::PhantomData,
    sync::{Arc, Mutex},
};

use anyhow::{anyhow, Result};
use casus::{Event, Waiter};
use dashmap::{mapref::entry::Entry, DashMap};
use flate2::bufread::ZlibDecoder;

use crate::{
    message::{
        ClientMessage, ClientMessageData, ClientOpCode, Msg, ServerMessage, ServerMessageData,
        ServerOpCode,
    },
    traits::{ClientSendAdapter, SleepAdapter, SpawnAdapter},
    utils::{now, rand_string},
};

#[derive(Clone, Debug)]
pub struct Client<S, E, L>
where
    S: SpawnAdapter + 'static,
    E: ClientSendAdapter + 'static,
    L: SleepAdapter + 'static,
{
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
    pub fn new(_spawn_adapter: S, send_adapter: E, _sleep_adapter: L) -> Self {
        Self {
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
            Msg::Binary(b) => self.decompress(&b)?,
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

    pub(crate) fn decompress(&self, bytes: &[u8]) -> Result<String> {
        let mut d = ZlibDecoder::new(bytes);
        let mut s = String::new();
        d.read_to_string(&mut s)?;
        Ok(s)
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
    pub(crate) fn new(client: Client<S, E, L>, channel: String) -> Self {
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

    pub(crate) fn push(&self, v: String) {
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

    #[allow(unused)]
    pub(crate) fn extend(&self, iter: impl Iterator<Item = String>) {
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
