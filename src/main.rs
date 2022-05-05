use anyhow::Result;
use clap::Parser;
use std::io::BufRead;
use tokio::runtime::Runtime;
use trust_dns_resolver::config::*;
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::error::ResolveErrorKind;
use trust_dns_resolver::lookup_ip::LookupIp;
use trust_dns_resolver::proto::op::ResponseCode;
use trust_dns_resolver::Resolver;
use trust_dns_resolver::TokioAsyncResolver;

fn is_vulnerable(lookup_result: &Result<LookupIp, ResolveError>) -> bool {
    match lookup_result {
        Ok(_) => false,
        Err(err) => match err.kind() {
            ResolveErrorKind::Message(_) => false,
            ResolveErrorKind::Msg(_) => false,
            ResolveErrorKind::NoConnections => false,
            ResolveErrorKind::NoRecordsFound {
                query: _,
                soa: _,
                negative_ttl: _,
                response_code,
                trusted: _,
            } => match response_code {
                ResponseCode::NoError => false,
                ResponseCode::FormErr => false,
                ResponseCode::ServFail => true,
                ResponseCode::NXDomain => false,
                ResponseCode::NotImp => false,
                ResponseCode::Refused => false,
                ResponseCode::YXDomain => false,
                ResponseCode::YXRRSet => false,
                ResponseCode::NXRRSet => false,
                ResponseCode::NotAuth => false,
                ResponseCode::NotZone => false,
                ResponseCode::BADVERS => false,
                ResponseCode::BADSIG => false,
                ResponseCode::BADKEY => false,
                ResponseCode::BADTIME => false,
                ResponseCode::BADMODE => false,
                ResponseCode::BADNAME => false,
                ResponseCode::BADALG => false,
                ResponseCode::BADTRUNC => false,
                ResponseCode::BADCOOKIE => false,
                ResponseCode::Unknown(_number) => false,
            },
            ResolveErrorKind::Io(_) => false,
            ResolveErrorKind::Proto(_) => false,
            ResolveErrorKind::Timeout => false,
            _ => false,
        },
    }
}

/// Tool to detect if a domain is vulnerable to domain server takeover.
/// If neither of -d or -i is specified, the list of domains will be read
/// from stdin.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Filename with a list of domains to check
    #[clap(short, long)]
    input_file: Option<String>,
    /// Domain to do the lookup for
    #[clap(short, long)]
    domain: Option<String>,
    /// If the lookups should be perfomed asynchronously or not
    #[clap(short, long)]
    r#async: bool,
}

fn check_async(to_check: &[String]) {
    let io_loop = Runtime::new().unwrap();

    let resolver = io_loop
        .block_on(async {
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
        })
        .expect("failed to connect resolver");

    let futures: Vec<_> = to_check.iter().map(|l| resolver.lookup_ip(l)).collect();

    // do these futures concurrently and return them
    let _ = io_loop
        .block_on(futures::future::join_all(futures))
        .into_iter()
        .map(|res| is_vulnerable(&res))
        .zip(to_check.iter())
        .map(|(is_vulnerable, domain)| {
            println!("{} : {}", domain, is_vulnerable);
        })
        .collect::<()>();
}

fn check(to_check: &[String]) {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();

    let _ = to_check
        .iter()
        .map(|l| {
            let is_vulnerable = is_vulnerable(&resolver.lookup_ip(l));
            println!("{} : {}", l, is_vulnerable);
        })
        .collect::<()>();
}

fn main() {
    let args = Args::parse();

    if args.input_file.is_some() && args.domain.is_some() {
        eprintln!("the --input_file option and the --domain option are mutually exclusive");
        std::process::exit(1);
    }

    let mut to_check: Vec<String> = vec![];

    if args.input_file.is_none() && args.domain.is_none() {
        for input in std::io::stdin().lock().lines() {
            to_check.push(input.unwrap().trim().to_string());
        }
    }

    if args.input_file.is_some() {
        let list = std::fs::read_to_string(&args.input_file.unwrap()).unwrap();

        for l in list.split('\n') {
            to_check.push(l.trim().to_string());
        }
    } else if args.domain.is_some() {
        to_check.push(args.domain.unwrap());
    }

    if args.r#async {
        check_async(&to_check);
    } else {
        check(&to_check);
    }
}
