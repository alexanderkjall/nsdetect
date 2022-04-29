use anyhow::Result;
use clap::Parser;
use trust_dns_resolver::config::*;
use trust_dns_resolver::error::ResolveErrorKind;
use trust_dns_resolver::proto::op::ResponseCode;
use trust_dns_resolver::Resolver;

fn is_vulnerable(domain_name: &str) -> Result<bool> {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();

    Ok(match resolver.lookup_ip(domain_name) {
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
    })
}

/// Tool to detect if a domain is vulnerable to domain server takeover
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Filename with a list of domains to check
    #[clap(short, long)]
    input_file: Option<String>,
    /// Domain to do the lookup for
    #[clap(short, long)]
    domain: Option<String>,
}

fn main() {
    let args = Args::parse();

    if args.input_file.is_some() && args.domain.is_some() {
        eprintln!("the --input_file option and the --domain option are mutually exclusive");
        std::process::exit(1);
    }
    if args.input_file.is_none() && args.domain.is_none() {
        eprintln!("one of the --input_file and --domain options must be set");
        std::process::exit(1);
    }

    if args.input_file.is_some() {
        let list = std::fs::read_to_string(&args.input_file.unwrap()).unwrap();

        for l in list.split('\n') {
            println!("{}: {}", l.trim(), is_vulnerable(l.trim()).unwrap());
        }
    } else if args.domain.is_some() {
        let d = &args.domain.unwrap();
        println!("{}: {}", d, is_vulnerable(d).unwrap());
    }
}
