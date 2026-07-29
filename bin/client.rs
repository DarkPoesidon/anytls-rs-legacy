use anytls::{BoxError, ClientArgs, resolve_client_config, runner_execute};
use clap::Parser;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let cancel_token = CancellationToken::new();
    let cancel_token_clone = cancel_token.clone();

    let ctrlc_future = ctrlc2::AsyncCtrlC::new(move || {
        log::trace!("Ctrl+C received, cancelling...");
        cancel_token_clone.cancel();
        true
    })?;

    let mut main_worker = tokio::spawn(run(cancel_token));

    tokio::select! {
        _ = ctrlc_future => {
            log::info!("Ctrl+C received, shutting down...");
            if let Err(e) = main_worker.await? {
                log::warn!("Main worker error: {}", e);
            }
        }
        res = &mut main_worker => {
            if let Err(e) = res? {
                log::warn!("Main worker error: {e}");
            }
        }
    }

    Ok(())
}

async fn run(cancel_token: CancellationToken) -> Result<(), BoxError> {
    use std::io::{Error, ErrorKind::InvalidInput};
    let args = ClientArgs::parse();

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(args.log.to_string())).init();

    let config = resolve_client_config(&args)?;

    use socks5_impl::protocol::ProxyType::{Http, Socks5};
    if args.listen.proxy_type != Socks5 && args.listen.proxy_type != Http {
        let err = "Only SOCKS5 or HTTP (both mixed actually) proxy type is supported for listen address";
        return Err(Error::new(InvalidInput, err).into());
    }

    if args.print_url {
        let uri = String::from(&config);
        println!("{}", uri);
        return Ok(());
    }

    if let Some(display_name) = &config.display_name {
        log::info!("[Client] Node: {}", display_name);
    }
    runner_execute(cancel_token, args).await?;
    Ok(())
}
