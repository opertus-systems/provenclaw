use provenclaw_host::Host;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = Host::discover()?;
    host.init_layout()?;
    println!("provenclawd ready at {}", host.paths().base_dir.display());
    Ok(())
}
