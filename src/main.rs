//! saltsh binary: dispatch to client or server, one static-friendly binary.

use std::process::ExitCode;

fn main() -> ExitCode {
    // Network daemons must not die on SIGPIPE; writes map to EPIPE instead.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    let args: Vec<String> = std::env::args().skip(1).collect();
    match saltsh::cli::parse(&args) {
        Ok(saltsh::cli::Command::Help) => {
            print!("{}", saltsh::cli::USAGE);
            ExitCode::SUCCESS
        }
        Ok(saltsh::cli::Command::Version) => {
            println!("{}", saltsh::cli::version_string());
            ExitCode::SUCCESS
        }
        Ok(saltsh::cli::Command::Serve(opts)) => match saltsh::server::run(opts) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("saltsh: {e}");
                ExitCode::FAILURE
            }
        },
        Ok(saltsh::cli::Command::Keygen(opts)) => {
            let path = opts.path.unwrap_or_else(|| {
                saltsh::util::home_dir()
                    .map(|h| h.join(".ssh/saltsh_ed25519"))
                    .unwrap_or_else(|| "saltsh_ed25519".into())
            });
            match saltsh::sshkeys::keygen(&path, opts.passphrase.as_deref(), &opts.comment) {
                Ok(kp) => {
                    println!(
                        "Generated Ed25519 keypair:\n  private: {}\n  public:  {}.pub\n  fingerprint: {}",
                        path.display(),
                        path.display(),
                        saltsh::tofu::fingerprint(&kp.public)
                    );
                    println!(
                        "Add this line to the server's authorized_keys:\n{}",
                        saltsh::sshkeys::authorized_keys_entry(&kp.public, &opts.comment).trim_end()
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("saltsh: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Ok(saltsh::cli::Command::Client(opts)) => match saltsh::client::run(opts) {
            Ok(code) => ExitCode::from((code & 0xFF) as u8),
            Err(e) => {
                eprintln!("saltsh: {e}");
                ExitCode::from(255)
            }
        },
        Err(e) => {
            eprintln!("saltsh: {e}");
            eprintln!("Try 'saltsh --help' for usage.");
            ExitCode::from(2)
        }
    }
}
