use std::env;
use std::process::{Command, Stdio};

#[test]
fn timeout_scenario() -> Result<(), std::io::Error> {
    let current_dir = env::current_dir()?;

    println!("The current directory is {}", current_dir.display());
    // Need to append to path
    let key = "PATH";
    let mut current_path = String::new();
    match env::var(key) {
        Ok(val) => current_path = val,
        Err(e) => println!("couldn't interpret {}: {}", key, e),
    }
    let new_path = format!(
        "{}/mocks:{}/target/debug:{}",
        current_dir.display(),
        current_dir.display(),
        current_path
    );
    println!("Running tests using this PATH: {}", new_path);
    let output_folder = format!("{}/{}", ".", "output");
    // Make a directory to store the generated zip file
    let _mkdir = match Command::new("mkdir").arg("-p").arg(&output_folder).spawn() {
        Err(why) => panic!("couldn't spawn mkdir: {}", why),
        Ok(process) => process,
    };
    // copy crictl to base_folder
    Command::new("cp")
        .arg("-f")
        .arg("./mocks/crictl-timeout.sh")
        .arg("../target/debug/crictl")
        .output()
        .expect("cp failed");

    // cat the test core file to process.
    let cat = Command::new("cat")
        .env("PATH", &new_path)
        .arg("./mocks/test.core")
        .stdout(Stdio::piped())
        .spawn()?
        .stdout
        .unwrap();

    let cdc = Command::new("../target/debug/core-dump-composer")
        .arg("-c")
        .arg("1000000000")
        .arg("-e")
        .arg("node")
        .arg("-p")
        .arg("4")
        .arg("-s")
        .arg("10")
        .arg("-E")
        .arg("!target!debug!core-dump-composer")
        .arg("-d")
        .arg(&output_folder)
        .arg("-t")
        .arg("1588462466")
        .arg("-h")
        .arg("crashing-app-699c49b4ff-86wrh")
        .arg("--timeout")
        .arg("1")
        .stdin(cat)
        .output()
        .expect("Couldn't execute");

    println!("{}", String::from_utf8_lossy(&cdc.stdout));
    println!("{}", String::from_utf8_lossy(&cdc.stderr));
    assert_eq!("timeout\n", String::from_utf8_lossy(&cdc.stdout));
    assert_eq!(1, *&cdc.status.code().unwrap());
    Ok(())
}
