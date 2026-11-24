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
            // Default output path is the client's default identity path, so
            // `saltsh keygen` followed by `saltsh <host>` just works.
            let path = opts.path.unwrap_or_else(|| {
                saltsh::util::home_dir()
                    .map(|h| h.join(".saltsh/id_ed25519"))
                    .unwrap_or_else(|| ".saltsh/id_ed25519".into())
            });
            // Passphrase: `-N pass` uses it verbatim, `-N ''` means no
            // passphrase, and omitting -N prompts (empty answer = none),
            // asking twice like ssh-keygen.
            let passphrase = match opts.passphrase {
                Some(p) if p.is_empty() => None,
                Some(p) => Some(p),
                None => match prompt_key_passphrase() {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("saltsh: {e}");
                        return ExitCode::FAILURE;
                    }
                },
            };
            match saltsh::sshkeys::keygen(&path, passphrase.as_deref(), &opts.comment) {
                Ok(kp) => {
                    println!(
                        "Generated Ed25519 keypair:\n  private: {}\n  public:  {}.pub\n  fingerprint: {}{}",
                        path.display(),
                        path.display(),
                        saltsh::tofu::fingerprint(&kp.public),
                        if passphrase.is_some() { "\n  (the private key is passphrase-protected)" } else { "" }
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

/// Interactive passphrase prompt for `saltsh keygen` (ssh-keygen style):
/// ask twice with echo off; an empty first answer means no passphrase.
fn prompt_key_passphrase() -> saltsh::Result<Option<String>> {
    let first = saltsh::pty::read_passphrase("Enter passphrase (empty for no passphrase): ")?;
    if first.is_empty() {
        return Ok(None);
    }
    let second = saltsh::pty::read_passphrase("Enter same passphrase again: ")?;
    if *first != *second {
        return Err(saltsh::Error::usage("passphrases do not match"));
    }
    Ok(Some(first.to_string()))
}
