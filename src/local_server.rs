extern crate std;
extern crate threadpool;
extern crate thrift;
extern crate unix_socket;

use std::sync::Arc;

use threadpool::ThreadPool;

use thrift::{
    ApplicationError,
    ApplicationErrorKind
};
use thrift::protocol::{
    TInputProtocolFactory,
    TOutputProtocolFactory,
    TInputProtocol,
    TOutputProtocol,
};
use thrift::transport::{
    TReadTransportFactory,
    TWriteTransportFactory,
};

use thrift::server::{
    TProcessor,
};

use stop_signal::*;

#[derive(Debug)]
pub struct LocalServer<PRC, RTF, IPF, WTF, OPF>
    where
        PRC: TProcessor + Send + Sync + 'static,
        RTF: TReadTransportFactory + 'static,
        IPF: TInputProtocolFactory + 'static,
        WTF: TWriteTransportFactory + 'static,
        OPF: TOutputProtocolFactory + 'static,
{
    r_trans_factory: RTF,
    i_proto_factory: IPF,
    w_trans_factory: WTF,
    o_proto_factory: OPF,
    processor: Arc<PRC>,
    worker_pool: ThreadPool,
}

impl<PRC, RTF, IPF, WTF, OPF> LocalServer<PRC, RTF, IPF, WTF, OPF>
    where PRC: TProcessor + Send + Sync + 'static,
          RTF: TReadTransportFactory + 'static,
          IPF: TInputProtocolFactory + 'static,
          WTF: TWriteTransportFactory + 'static,
          OPF: TOutputProtocolFactory + 'static {

    pub fn new(
        read_transport_factory: RTF,
        input_protocol_factory: IPF,
        write_transport_factory: WTF,
        output_protocol_factory: OPF,
        processor: PRC,
        num_workers: usize,
    ) -> LocalServer<PRC, RTF, IPF, WTF, OPF> {
        LocalServer {
            r_trans_factory: read_transport_factory,
            i_proto_factory: input_protocol_factory,
            w_trans_factory: write_transport_factory,
            o_proto_factory: output_protocol_factory,
            processor: Arc::new(processor),
            worker_pool: ThreadPool::with_name(
                "Thrift service processor".to_owned(),
                num_workers,
            ),
        }
    }

    fn bind(listen_address: &str) -> thrift::Result<super::sys::TListener> {
        if cfg!(target_family = "unix") {
            let socket = unix_socket::UnixListener::bind(listen_address)?;
            Ok(socket)
        } else {
            unimplemented!();
        }
    }

    pub fn listen(&mut self, listen_address: &str, done: StopSignal) -> thrift::Result<()> {
        let listener = Self::bind(listen_address)?;
        listener.set_nonblocking(true)?;
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    let (i_prot, o_prot) = self.new_protocols_for_connection(s)?;
                    let processor = self.processor.clone();
                    self.worker_pool
                        .execute(move || handle_incoming_connection(processor, i_prot, o_prot),);
                }
                Err(_) => {}
            }
            if done.wait_timeout(std::time::Duration::from_millis(100)) {
                break
            }
        }

        Err(
            thrift::Error::Application(
                ApplicationError {
                    kind: ApplicationErrorKind::Unknown,
                    message: "aborted listen loop".into(),
                },
            ),
        )
    }

    fn new_protocols_for_connection(
        &mut self,
        stream: super::sys::TChannel,
    ) -> thrift::Result<(Box<TInputProtocol + Send>, Box<TOutputProtocol + Send>)> {
        // split it into two - one to be owned by the
        // input tran/proto and the other by the output
        let w_chan = stream.try_clone()?;
        let r_chan = stream;

        // input protocol and transport
        let r_tran = self.r_trans_factory.create(Box::new(r_chan));
        let i_prot = self.i_proto_factory.create(r_tran);

        // output protocol and transport
        let w_tran = self.w_trans_factory.create(Box::new(w_chan));
        let o_prot = self.o_proto_factory.create(w_tran);

        Ok((i_prot, o_prot))
    }
}

fn handle_incoming_connection<PRC>(
    processor: Arc<PRC>,
    i_prot: Box<TInputProtocol>,
    o_prot: Box<TOutputProtocol>,
) where
    PRC: TProcessor,
{
    let mut i_prot = i_prot;
    let mut o_prot = o_prot;
    loop {
        let r = processor.process(&mut *i_prot, &mut *o_prot);
        if let Err(e) = r {
            debug_println!("WARN: processor completed with error: {:?}", e);
            break;
        }
    }
}
