extern crate dotenv;

use advisory_lock::{AdvisoryFileLock, FileLockMode};
use libcrio::Cli;
use log::{debug, error, info};
use serde_json::json;
use std::env;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::process;
use std::process::Command;
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;
use uuid::Uuid;
use zip::write::FileOptions;
use zip::ZipWriter;

mod config;
mod logging;

fn main() -> Result<(), anyhow::Error> {
    let (send, recv) = channel();
    let cc = config::CoreConfig::new()?;
    let timeout = cc.params.timeout;

    thread::spawn(move || {
        let result = handle(cc);
        send.send(result).unwrap();
    });

    let result = recv.recv_timeout(Duration::from_secs(timeout));

    match result {
        Ok(inner_result) => inner_result,
        Err(_error) => {
            println!("timeout");
            process::exit(1);
        }
    }
}

fn handle(mut cc: config::CoreConfig) -> Result<(), anyhow::Error> {
    cc.set_namespace("default".to_string());
    let l_log_level = cc.log_level.clone();
    let log_path = logging::init_logger(l_log_level)?;
    debug!("Arguments: {:?}", env::args());

    info!(
        "Environment config:\n IGNORE_CRIO={}\nCRIO_IMAGE_CMD={}\nUSE_CRIO_CONF={}",
        cc.ignore_crio, cc.image_command, cc.use_crio_config
    );

    info!("Set logfile to: {:?}", &log_path);
    debug!("Creating dump for {}", cc.get_templated_name());

    // save core dump to disk so we can extract the env vars using grep
    let tmp_uuid = Uuid::new_v4();
    let core_path = format!("/tmp/tmp_{}.core", tmp_uuid);
    {
        let mut core_file = match File::create(core_path.clone()) {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to create file: {}", e);
                process::exit(1);
            }
        };
        core_file.lock(FileLockMode::Exclusive)?;

        let stdin = io::stdin();
        let mut stdin = stdin.lock();

        match io::copy(&mut stdin, &mut core_file) {
            Ok(v) => v,
            Err(e) => {
                error!("Error writing core file \n{}", e);
                process::exit(1);
            }
        };
        core_file.flush()?;
        core_file.unlock()?;
    }

    let env_var_name = "POD_NAME=";
    let get_podname_exec = Command::new("sh")
        .arg("-c")
        .arg(format!("strings -a {} | grep {}", core_path, env_var_name))
        .output()
        .expect("failed to execute process");

    let podname_env_output = String::from_utf8(get_podname_exec.stdout)?;
    
    // if we couldn't find the podname env variable then default to hostname
    let podname_str = if podname_env_output.is_empty() {
        cc.params.hostname.clone()
    }
    else {
        // strip out 'POD_NAME=' from the returned string
        let podname_env_err = String::from_utf8(get_podname_exec.stderr)?;
        let pn_start = env_var_name.len();
        let pn_end = podname_env_output.len();

        if pn_end <= pn_start {
            error!("Failed to remove {} from {}. pn_start: {}. pn_end: {}. Error: {}", env_var_name, podname_env_output, pn_start, pn_end, podname_env_err);
            process::exit(1);
        }
    
        String::from(&podname_env_output[pn_start..pn_end])
    };

    // extract the core dump saved to disk
    let mut core_buffer = Vec::new();
    {
        let mut core_file = match File::open(core_path.clone()) {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to open file: {}", e);
                process::exit(1);
            }
        };

        // read the whole file and delete it
        core_file.read_to_end(&mut core_buffer)?;
    }

    // delete the emp core dump
    std::fs::remove_file(core_path.clone())?;

    let l_crictl_config_path = cc.crictl_config_path.clone();

    let config_path = if cc.use_crio_config {
        Some(
            l_crictl_config_path
                .into_os_string()
                .to_string_lossy()
                .to_string(),
        )
    } else {
        None
    };
    let l_bin_path = cc.bin_path.clone();
    let l_image_command = cc.image_command.clone();
    let cli = Cli {
        bin_path: l_bin_path,
        config_path,
        image_command: l_image_command,
    };

    let pod_object = match cli.pod(&podname_str) {
        Ok(v) => v,
        Err(e) => {
            error!("{}", e);
            // We fall through here as the coredump and info can still be captured.
            json!({})
        }
    };

    // match the label filter if there's one, and skip the whole process if it doesn't match
    if !cc.pod_selector_label.is_empty() {
        debug!(
            "Pod selector specified. Will record only if pod has label {}",
            &cc.pod_selector_label
        );
        let pod_labels = pod_object["labels"].as_object().unwrap();
        // check if pod_labels has pod_selector_label
        if pod_labels.get(&cc.pod_selector_label).is_none() {
            info!(
                "Skipping pod as it did not match selector label {}",
                &cc.pod_selector_label
            );
            process::exit(0);
        }
    } else {
        debug!("No pod selector specified, selecting all pods");
    }

    let namespace = pod_object["metadata"]["namespace"]
        .as_str()
        .unwrap_or("unknown");

    cc.set_namespace(namespace.to_string());

    let podname = pod_object["metadata"]["name"].as_str().unwrap_or("unknown");

    cc.set_podname(podname.to_string());

    // Create the base zip file that we are going to put everything into
    let compression_method = if cc.disable_compression {
        zip::CompressionMethod::Stored
    } else {
        zip::CompressionMethod::Deflated
    };
    let options = FileOptions::default()
        .compression_method(compression_method)
        .unix_permissions(0o444)
        .large_file(true);

    let file = match File::create(cc.get_zip_full_path()) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to create file: {}", e);
            process::exit(1);
        }
    };
    file.lock(FileLockMode::Exclusive)?;
    let mut zip = ZipWriter::new(&file);

    debug!(
        "Create a JSON file to store the dump meta data\n{}",
        cc.get_dump_info_filename()
    );

    match zip.start_file(cc.get_dump_info_filename(), options) {
        Ok(v) => v,
        Err(e) => {
            error!("Error starting dump file in zip \n{}", e);
            zip.finish()?;
            file.unlock()?;
            process::exit(1);
        }
    };

    match zip.write_all(cc.get_dump_info().as_bytes()) {
        Ok(v) => v,
        Err(e) => {
            error!("Error writing pod file in zip \n{}", e);
            zip.finish()?;
            file.unlock()?;
            process::exit(1);
        }
    };

    // Pipe the core file to zip
    match zip.start_file(cc.get_core_filename(), options) {
        Ok(v) => v,
        Err(e) => error!("Error starting core file \n{}", e),
    };

    match zip.write_all(&mut core_buffer) {
        Ok(v) => v,
        Err(e) => {
            error!("Error writing core file \n{}", e);
            process::exit(1);
        }
    };
    zip.flush()?;

    if cc.ignore_crio {
        zip.finish()?;
        file.unlock()?;
        process::exit(0);
    }

    // let l_crictl_config_path = cc.crictl_config_path.clone();

    // let config_path = if cc.use_crio_config {
    //     Some(
    //         l_crictl_config_path
    //             .into_os_string()
    //             .to_string_lossy()
    //             .to_string(),
    //     )
    // } else {
    //     None
    // };
    // let l_bin_path = cc.bin_path.clone();
    // // let image_command = if cc.image_command == *"image" {
    // //     libcrio::ImageCommand::Images
    // // } else {
    // //     libcrio::ImageCommand::Img
    // // };
    // let cli = Cli {
    //     bin_path: l_bin_path,
    //     config_path,
    //     image_command
    // };

    // let l_pod_filename = cc.get_pod_filename().clone();
    debug!("Using runtime_file_name:{}", cc.get_pod_filename());

    match zip.start_file(cc.get_pod_filename(), options) {
        Ok(v) => v,
        Err(e) => {
            error!("Error starting pod file in zip \n{}", e);
            zip.finish()?;
            file.unlock()?;
            process::exit(1);
        }
    };

    match zip.write_all(pod_object.to_string().as_bytes()) {
        Ok(v) => v,
        Err(e) => {
            error!("Error writing pod file in zip \n{}", e);
            zip.finish()?;
            file.unlock()?;
            process::exit(1);
        }
    };

    // TODO: Check logging of more than one pod retured
    let pod_id = match pod_object["id"].as_str() {
        Some(v) => v,
        None => {
            error!("Failed to get pod id");
            zip.finish()?;
            file.unlock()?;
            process::exit(1);
        }
    };

    // With the pod_id get the runtime information from crictl
    debug!("Getting inspectp output using pod_id:{}", pod_id);

    let inspectp = match cli.inspect_pod(pod_id) {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to inspect pod {}", e);
            json!({})
        }
    };
    debug!("Starting inspectp file\n{}", cc.get_inspect_pod_filename());
    match zip.start_file(cc.get_inspect_pod_filename(), options) {
        Ok(v) => v,
        Err(e) => {
            error!("Error starting inspect pod file in zip \n{}", e);
            zip.finish()?;
            file.unlock()?;
            process::exit(1);
        }
    };
    debug!("Writing inspectp file\n{}", cc.get_inspect_pod_filename());
    match zip.write_all(inspectp.to_string().as_bytes()) {
        Ok(v) => v,
        Err(e) => {
            error!("Error writing inspect pod file in zip \n{}", e);
            zip.finish()?;
            file.unlock()?;
            process::exit(1);
        }
    };

    // Get the container_image_name based on the pod_id
    let ps_object = match cli.pod_containers(pod_id) {
        Ok(v) => v,
        Err(e) => {
            error!("{}", e);
            zip.finish()?;
            file.unlock()?;
            process::exit(1);
        }
    };

    debug!("Starting ps file \n{}", cc.get_ps_filename());
    match zip.start_file(cc.get_ps_filename(), options) {
        Ok(v) => v,
        Err(e) => {
            error!("Error starting ps file in zip \n{}", e);
            zip.finish()?;
            file.unlock()?;
            process::exit(1);
        }
    };

    debug!("Writing ps file \n{}", cc.get_ps_filename());
    match zip.write_all(ps_object.to_string().as_bytes()) {
        Ok(v) => v,
        Err(e) => {
            error!("Error writing ps file in zip \n{}", e);
            zip.finish()?;
            file.unlock()?;
            process::exit(1);
        }
    };

    debug!("Successfully got the process details {}", ps_object);

    if let Some(containers) = ps_object["containers"].as_array() {
        for (counter, container) in containers.iter().enumerate() {
            let img_ref = match container["imageRef"].as_str() {
                Some(v) => v,
                None => {
                    error!("Failed to get containerid {}", "");
                    break;
                }
            };
            let log =
                match cli.tail_logs(container["id"].as_str().unwrap_or_default(), cc.log_length) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("Error finding logs:\n{}", e);
                        "".to_string()
                    }
                };
            debug!("Starting log file \n{}", cc.get_log_filename(counter));
            match zip.start_file(cc.get_log_filename(counter), options) {
                Ok(v) => v,
                Err(e) => {
                    error!("Error starting log file in zip \n{}", e);
                    zip.finish()?;
                    file.unlock()?;
                    process::exit(1);
                }
            };
            debug!("Writing file output \n{}", log);
            // TODO: Should this be streamed?
            match zip.write_all(log.to_string().as_bytes()) {
                Ok(v) => v,
                Err(e) => {
                    error!("Error writing log file in zip \n{}", e);
                    zip.finish()?;
                    file.unlock()?;
                    process::exit(1);
                }
            };
            debug!("found img_id {}", img_ref);
            let image = match cli.image(img_ref) {
                Ok(v) => v,
                Err(e) => {
                    error!("Error finding image:\n{}", e);
                    json!({})
                }
            };

            debug!("Starting image file \n{}", cc.get_image_filename(counter));
            match zip.start_file(cc.get_image_filename(counter), options) {
                Ok(v) => v,
                Err(e) => {
                    error!("Error starting ps file in zip \n{}", e);
                    zip.finish()?;
                    file.unlock()?;
                    process::exit(1);
                }
            };
            debug!("Writing image file \n{}", cc.get_image_filename(counter));
            match zip.write_all(image.to_string().as_bytes()) {
                Ok(v) => v,
                Err(e) => {
                    error!("Error writing ps file in zip \n{}", e);
                    zip.finish()?;
                    file.unlock()?;
                    process::exit(1);
                }
            };
            debug!(
                "Getting logs for container id {}",
                container["id"].as_str().unwrap_or_default()
            );
        }
    };

    zip.finish()?;
    file.unlock()?;
    Ok(())
}
