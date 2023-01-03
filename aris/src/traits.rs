use std::{fmt::Debug, future::Future};

use anyhow::Result;

use crate::message::Msg;

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
