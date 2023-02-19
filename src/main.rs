use crate::key::{KeyUsageTarget, SepKey};
use byteorder::{BigEndian, WriteBytesExt};
use clap::Parser;
use eyre::{bail, ensure, eyre};
use inquire::{Confirm, Select};
use log::info;
use ssh_agent_lib::agent::Agent;
use ssh_agent_lib::proto::Message::{IdentitiesAnswer, SignResponse, Success};
use ssh_agent_lib::proto::{Blob, Identity, Message, SignRequest, Signature, SignatureBlob};
use std::collections::HashMap;
use std::os::unix::fs::{symlink, FileTypeExt};
use std::path::PathBuf;
use std::process::Command;
use std::{env, fs};

mod github;
mod key;

const GITLAB: &str = "gitlab";
const GITHUB: &str = "github";
const NONE: &str = "none";
const APP_NAME: &str = "io.jbaker.cs";
const PLIST: &str = "io.jbaker.cs.plist";

#[derive(clap::Parser)]
struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(clap::Subcommand)]
enum Action {
    Install,
    Uninstall,
    Serve,
}

struct CommitSigningApp {
    work_dir: PathBuf,
    launch_agent: PathBuf,
}

impl CommitSigningApp {
    fn key(&self, usage: KeyUsageTarget) -> eyre::Result<SepKey> {
        SepKey::create(&self.work_dir, usage)
    }

    fn sock_file(&self) -> PathBuf {
        self.work_dir.join("ssh.sock")
    }

    fn serve(&self) -> eyre::Result<()> {
        ensure!(
            env::current_exe().unwrap().parent().unwrap() == self.work_dir,
            "cs does not appear to have been successfully installed"
        );
        let comms_key = self.key(KeyUsageTarget::Comms)?;
        let signing_key = self.key(KeyUsageTarget::Signing)?;

        let sock_file = self.sock_file();
        if sock_file.exists() {
            ensure!(
                fs::metadata(&sock_file)?.file_type().is_socket(),
                "socket file exists but somehow is not a socket. this is unexpected"
            );
            fs::remove_file(&sock_file)?;
        }

        if let Ok(current_sock) = env::var("SSH_AGENT_SOCK") {
            symlink(&sock_file, current_sock)?;
        }

        let mut keys = HashMap::new();
        keys.insert(comms_key.pubkey_bytes.clone(), comms_key);
        keys.insert(signing_key.pubkey_bytes.clone(), signing_key);
        Keys { keys }
            .run_unix(sock_file)
            .map_err(|err| eyre!("wrapped: {err:?}"))
    }

    fn install(&self) -> eyre::Result<()> {
        ensure!(Confirm::new("please confirm that you wish to install cs. note that this will replace the ssh-agent \
        used and so if you need to use specific keys for specific services, you will need to set specific ~/.ssh/config").prompt()?,
            "user did not confirm that they wished to install");

        println!(
            "Copying application to working directory ({:?})",
            self.work_dir
        );
        fs::create_dir_all(&self.work_dir)?;
        let exe = env::current_exe()?;
        let app_target = self.work_dir.join("cs");
        let app_target_str = self.work_dir.join("cs").to_str().unwrap().to_string();
        fs::copy(exe, app_target)?;
        println!("copied application to working directory.");

        let comms_key = self.key(KeyUsageTarget::Comms)?;
        let signing_key = self.key(KeyUsageTarget::Signing)?;

        println!("configuring git");
        run_git_command(&["config", "--global", "gpg.format", "ssh"])?;
        run_git_command(&["config", "--global", "commit.gpgsign", "true"])?;
        run_git_command(&[
            "config",
            "--global",
            "user.signingkey",
            &signing_key.pubkey_file,
        ])?;
        println!("git configured successfully");

        let code_storage = Select::new(
            "Would you like to automatically configure a code storage solution to trust your keys?",
            vec![GITHUB, GITLAB, NONE],
        )
        .prompt()?;

        if code_storage == GITHUB {
            github::register_keys(&comms_key.pubkey_string, &signing_key.pubkey_string)?;
        } else if code_storage == GITLAB {
            println!("gitlab support is coming if there is interest. for now, please configure manually.")
        }
        let comms_key_path_string = &comms_key.pubkey_file;
        let signing_key_path_string = &signing_key.pubkey_file;
        println!(
            "In any case, if you'd like to set up a different code storage system, you can find \
            the relevant public keys here:\n\
            \t key for communications: {comms_key_path_string}\n\
            \t key for signing: {signing_key_path_string}\n\
            Please be sure to only trust the signing key for code signing, because the comms key\
            does not require biometric authentication."
        );

        println!("Configured code storage to trust our keys");

        println!("Adding LaunchCtl unit to run our SSH agent in the background");
        let launchctl_config = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
            <plist version=\"1.0\">\n\
            <dict>\n\
            <key>RunAtLoad</key>\n\
            <true/>\n\
            <key>KeepAlive</key>\n\
            <true/>\n\
            <key>Label</key>\n\
            <string>io.jbaker.cs.restart</string>\n\
            <key>ProgramArguments</key>\n\
            <array>\n\
            <string>{app_target_str}</string>\n\
            <string>serve</string>\n\
            </array>\n\
            </dict>\n\
            </plist>");
        fs::write(&self.launch_agent, launchctl_config)?;
        println!("wrote launch agent configuration: {:?}", self.launch_agent);
        let cmd = Command::new("launchctl")
            .args(["load", "-w", self.launch_agent.to_str().unwrap()])
            .status()?;
        ensure!(
            cmd.success(),
            "error while loading into launchctl, code: {:?}",
            cmd.code()
        );

        Ok(())
    }

    fn uninstall(&self) -> eyre::Result<()> {
        ensure!(
            Confirm::new("please confirm that you wish to uninstall cs").prompt()?,
            "user did not confirm that they wished to uninstall"
        );

        println!("Unloading launchctl agent");
        let cmd = Command::new("launchctl")
            .args(["unload", "-w", self.launch_agent.to_str().unwrap()])
            .status()?;
        ensure!(
            cmd.success(),
            "error while loading into launchctl, code: {:?}",
            cmd.code()
        );
        println!("Unloaded launchctl agent");

        println!("Removing launchctl agent");
        fs::remove_file(&self.launch_agent)?;
        println!("Removed launchctl agent");

        if Confirm::new(
            "Would you like to delete keys from the secure enclave? \
        If this is done it cannot be undone. If not done, if the application is reinstalled \
        the same keys will be reused",
        )
        .prompt()?
        {
            println!("Deleting signing keys");
            SepKey::delete_all()?;
            println!("Deleted signing keys");
        }

        println!("Deleting contents of work dir");
        fs::remove_dir_all(&self.work_dir)?;
        println!("Deleted contents of work dir");

        Ok(())
    }
}

fn main() -> eyre::Result<()> {
    env_logger::init();
    let args = Args::parse();
    let home_dir = PathBuf::from(env::var("HOME")?);
    let work_dir = home_dir.join("Application Support").join(APP_NAME);
    let launch_agent = home_dir.join("Library").join("LaunchAgents").join(PLIST);

    let app = CommitSigningApp {
        work_dir,
        launch_agent,
    };

    match args.action {
        Action::Install => app.install(),
        Action::Serve => app.serve(),
        Action::Uninstall => app.uninstall(),
    }
}

fn run_git_command(args: &[&str]) -> eyre::Result<()> {
    println!("running git command: git {:?}", args);
    let result = Command::new("git").args(args).status()?;
    ensure!(
        result.success(),
        "git command not successful. Exit status {:?}",
        result.code()
    );
    Ok(())
}

struct Keys {
    keys: HashMap<Vec<u8>, SepKey>,
}

impl Agent for Keys {
    type Error = eyre::Error;

    fn handle(&self, message: Message) -> eyre::Result<Message> {
        match message {
            Message::RequestIdentities => Ok(IdentitiesAnswer(self.identities()?)),
            Message::SignRequest(request) => Ok(SignResponse(self.sign(request)?)),
            Message::Extension(_) => Ok(Success),
            _ => {
                bail!("unsupported kind of message")
            }
        }
    }
}

impl Keys {
    fn identities(&self) -> eyre::Result<Vec<Identity>> {
        info!("identities");
        Ok(self
            .keys
            .iter()
            .map(|(key, value)| Identity {
                pubkey_blob: key.clone(),
                comment: value.curve_type().to_string(),
            })
            .collect())
    }

    fn sign(&self, request: SignRequest) -> eyre::Result<SignatureBlob> {
        ensure!(request.flags == 0, "flags not supported");
        let Some(key) = self.keys.get(&request.pubkey_blob) else { bail!("could not find key") };
        let sig = key.sign(&request.data)?;

        let mut out = Vec::new();
        out.write_u32::<BigEndian>(sig.r.len() as u32)?;
        out.extend(sig.r.0);
        out.write_u32::<BigEndian>(sig.s.len() as u32)?;
        out.extend(sig.s.0);
        Ok(Signature {
            algorithm: key.curve_type().to_string(),
            blob: out,
        }
        .to_blob()?)
    }
}
