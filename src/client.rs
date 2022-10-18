use std::{sync::Arc, time::Duration};

use futures_util::sink::SinkExt;
use snarkvm::dpc::{testnet2::Testnet2, Address};
use tokio::{
    net::TcpStream,
    sync::{
        mpsc,
        mpsc::{Receiver, Sender},
        Mutex,
    },
    task,
    time::{sleep, timeout},
};
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;
use tracing::{debug, error, info, warn};

use crate::{message::{Code, ProverMessage}, prover::ProverEvent};
use bytes::{BytesMut, BufMut};
use std::io::{Write, Read};

pub struct Client {
    account: Option<String>,
    worker: Option<String>,
    address: Option<Address<Testnet2>>,
    server: String,
    sender: Arc<Sender<ProverMessage>>,
    receiver: Arc<Mutex<Receiver<ProverMessage>>>,
}

impl Client {
    pub fn init(account: Option<String>, worker: Option<String>, address: Option<Address<Testnet2>>, server: String) -> Arc<Self> {
        let (sender, receiver) = mpsc::channel(1024);
        Arc::new(Self {
            account,
            worker,
            address,
            server,
            sender: Arc::new(sender),
            receiver: Arc::new(Mutex::new(receiver)),
        })
    }

    pub fn sender(&self) -> Arc<Sender<ProverMessage>> {
        self.sender.clone()
    }

    pub fn receiver(&self) -> Arc<Mutex<Receiver<ProverMessage>>> {
        self.receiver.clone()
    }
}

pub fn start(prover_sender: Arc<Sender<ProverEvent>>, client: Arc<Client>) {
    task::spawn(async move {
        let receiver = client.receiver();
        loop {
            info!("Connecting to server...");
            match timeout(Duration::from_secs(5), TcpStream::connect(&client.server)).await {
                Ok(socket) => match socket {
                    Ok(socket) => {
                        info!("Connected to {}", client.server);
                        let mut framed = Framed::new(socket, ProverMessage::Canary);

                        let worker = client.worker.as_ref().unwrap().clone();
                        let authorization = match &client.account {
                            Some(account) => ProverMessage::Authorize(account.clone(), worker, String::new(), *ProverMessage::version()),
                            None => ProverMessage::Authorize(client.address.as_ref().unwrap().to_string(), worker, String::new(), *ProverMessage::version())
                        };

                        if let Err(e) = framed.send(authorization).await {
                            error!("Error sending authorization: {}", e);
                        } else {
                            debug!("Sent authorization");
                        }
                        let receiver = &mut *receiver.lock().await;
                        while receiver.try_recv().is_ok() {}
                        loop {
                            tokio::select! {
                                Some(message) = receiver.recv() => {
                                    // let message = message.clone();
                                    let name = message.name();
                                    debug!("Sending {} to server", name);
                                    if let Err(e) = framed.send(message).await {
                                        error!("Error sending {}: {:?}", name, e);
                                    }
                                }
                                result = framed.next() => match result {
                                    Some(Ok(message)) => {
                                        debug!("Received {} from server", message.name());
                                        match message {
                                            ProverMessage::AuthorizeResult(result, message) => {
                                                if result {
                                                    debug!("Authorized");
                                                } else if let Some(message) = message {
                                                    error!("Authorization failed: {}", message);
                                                    sleep(Duration::from_secs(5)).await;
                                                    break;
                                                } else {
                                                    error!("Authorization failed");
                                                    sleep(Duration::from_secs(5)).await;
                                                    break;
                                                }
                                            }
                                            ProverMessage::Notify(block_template, pool_target) => {
                                                if let Err(e) = prover_sender.send(ProverEvent::NewWork(pool_target, block_template)).await {
                                                    error!("Error sending work to prover: {}", e);
                                                } else {
                                                    debug!("Sent work to prover");
                                                }
                                            }
                                            ProverMessage::SubmitResult(code, message) => {
                                                match code {
                                                    Code::ProxyException => {
                                                        warn!("Proxy has an exception, skip statistics");
                                                    }
                                                    _ => {
                                                        if let Err(e) = prover_sender.send(ProverEvent::Result(Code::Success == code, message)).await {
                                                            error!("Error sending share result to prover: {}", e);
                                                        } else {
                                                            debug!("Sent share result to prover");
                                                        }
                                                    }
                                                }
                                            }
                                            _ => {
                                                debug!("Unhandled message: {}", message.name());
                                            }
                                        }
                                    }
                                    Some(Err(e)) => {
                                        warn!("Failed to read the message: {:?}", e);
                                    }
                                    None => {
                                        error!("Disconnected from server");
                                        sleep(Duration::from_secs(5)).await;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to connect to operator: {}", e);
                        sleep(Duration::from_secs(5)).await;
                    }
                },
                Err(_) => {
                    error!("Failed to connect to operator: Timed out");
                    sleep(Duration::from_secs(5)).await;
                }
            }
        }
    });
}
