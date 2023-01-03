use anyhow::Result;
use hmac::Mac;

use crate::{
    traits::PublishAdapter,
    utils::{now, rand_string},
    HmacSha256,
};

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
