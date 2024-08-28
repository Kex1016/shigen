#![windows_subsystem = "windows"]

use std::str::FromStr;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use tide::prelude::*;
use tide::{Error, Request};

use sysinfo::{Components, Disks, Networks, Pid, ProcessesToUpdate, System, Uid, Users, Groups};
use tide::http::headers::HeaderValue;
use tide::security::Origin;

#[derive(Debug, Deserialize)]
struct SystemInfo {
    os: String,
    kernel_version: String,
    os_version: String,
    uptime: u64,
    hostname: String,
}

#[derive(Debug, Deserialize)]
struct CpuInfo {
    cpu_name: String,
    cpu_cores: u32,
    cpu_frequency: u64,
    cpu_usage: Vec<CpuUsage>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CpuUsage {
    cpu_usage: f32,
    cpu_usage_per_core: Vec<f32>,
}

struct RamInfo {
    ram_total: u64,
    ram_free: u64,
    swap_total: u64,
    swap_free: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct DiskInfo {
    disk_name: String,
    disk_filesystem: String,
    disk_mount_point: String,
    disk_total: u64,
    disk_free: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct NetworkInfo {
    network_name: String,
    network_data: NetworkTransmit,
}

#[derive(Debug, Deserialize, Serialize)]
struct NetworkTransmit {
    received: u64,
    transmitted: u64,
    total_received: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct ProcessInfo {
    process_name: String,
    process_id: u32,
    process_memory: u64,
    process_cpu: f32,
    process_run_time: u64,
    process_thread_kind: String,
    process_executable: Option<String>,
    process_parent: Option<u32>,
    process_uid: String,
    process_gid: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct TempInfo {
    temp_name: String,
    temp_value: f32,
    temp_critical: Option<f32>,
}

// A macro to pass the sys variable to a function
macro_rules! pass_var {
    ($var:ident, $block:expr) => {
        {
            let $var = Arc::clone(&$var); // Clone Arc for the closure
            move |req: Request<()>| {
                let $var = Arc::clone(&$var); // Clone again for async function
                async move {
                    $block(req, $var).await
                }
            }
        }
    };

    ($var1:ident, $var2:ident, $block:expr) => {
        {
            let $var1 = Arc::clone(&$var1);
            let $var2 = Arc::clone(&$var2);
            move |req: Request<()>| {
                let $var1 = Arc::clone(&$var1);
                let $var2 = Arc::clone(&$var2);
                async move {
                    $block(req, $var1, $var2).await
                }
            }
        }
    }
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    tide::log::with_level(tide::log::LevelFilter::Info);
    let mut app = tide::new();

    let sys = Arc::new(Mutex::new(System::new_all()));
    let dsk = Arc::new(Mutex::new(Disks::new()));
    let net = Arc::new(Mutex::new(Networks::new()));
    let prc = Arc::new(Mutex::new(Components::new()));
    let usr = Arc::new(Mutex::new(Users::new()));
    let grp = Arc::new(Mutex::new(Groups::new()));

    // CORS
    app.with(tide::security::CorsMiddleware::new()
                 .allow_methods("GET, POST, OPTIONS".parse::<HeaderValue>().unwrap())
                 .allow_origin(Origin::from("*"))
                 .allow_credentials(false));

    app.at("/").get(|_| async { Ok("Hello, World!") });
    app.at("/system").get(get_system_info);
    app.at("/system/shutdown").post(shutdown_system);
    app.at("/system/reboot").post(restart_system);
    app.at("/cpu").get(pass_var!(sys, get_cpu_info));
    app.at("/memory").get(pass_var!(sys, get_ram_info));
    app.at("/disks").get(pass_var!(dsk, get_disk_info));
    app.at("/network").get(pass_var!(net, get_network_info));
    app.at("/processes")
        .get(pass_var!(sys, get_process_info))
        .post(pass_var!(sys, kill_process));
    app.at("/temps").get(pass_var!(prc, get_temps_info));
    app.at("/user/:id").get(pass_var!(usr, grp, get_user_info));

    // Get the port from the environment variable
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());

    app.listen("0.0.0.0:".to_string() + &port).await?;

    Ok(())
}

async fn get_system_info(_req: Request<()>) -> tide::Result {
    let res = SystemInfo {
        os: System::name().unwrap_or_default(),
        kernel_version: System::kernel_version().unwrap_or_default(),
        os_version: System::os_version().unwrap_or_default(),
        uptime: System::uptime(),
        hostname: System::host_name().unwrap_or_default(),
    };

    Ok(json!({
        "os": res.os,
        "kernel_version": res.kernel_version,
        "os_version": res.os_version,
        "uptime": res.uptime,
        "hostname": res.hostname
    }).into())
}

async fn get_cpu_info(_req: Request<()>, sys: Arc<Mutex<System>>) -> tide::Result {
    let mut sys = sys.lock().unwrap();

    sys.refresh_cpu_all();
    let cpu = sys.cpus();

    let res = CpuInfo {
        cpu_name: cpu[0].brand().to_string(),
        cpu_cores: cpu.len() as u32,
        cpu_frequency: cpu[0].frequency(),
        cpu_usage: vec![CpuUsage {
            cpu_usage: sys.global_cpu_usage(),
            cpu_usage_per_core: cpu.iter().map(|c| c.cpu_usage()).collect(),
        }],
    };

    Ok(json!({
        "cpu_name": res.cpu_name,
        "cpu_cores": res.cpu_cores,
        "cpu_frequency": res.cpu_frequency,
        "cpu_usage": res.cpu_usage
    }).into())
}

async fn get_ram_info(_req: Request<()>, sys: Arc<Mutex<System>>) -> tide::Result {
    let mut sys = sys.lock().unwrap();

    sys.refresh_memory();

    let ram = RamInfo {
        ram_total: sys.total_memory(),
        ram_free: sys.free_memory(),
        swap_total: sys.total_swap(),
        swap_free: sys.free_swap(),
    };

    Ok(json!({
        "ram_total": ram.ram_total,
        "ram_free": ram.ram_free,
        "swap_total": ram.swap_total,
        "swap_free": ram.swap_free
    }).into())
}

async fn get_disk_info(_req: Request<()>, sys: Arc<Mutex<Disks>>) -> tide::Result {
    let mut dsk = sys.lock().unwrap();

    dsk.refresh_list();

    let res = dsk.list().iter().map(|disk| {
        DiskInfo {
            disk_name: disk.name().to_str().unwrap_or_default().to_string(),
            disk_filesystem: disk.file_system().to_str().unwrap_or_default().to_string(),
            disk_mount_point: disk.mount_point().to_str().unwrap_or_default().to_string(),
            disk_total: disk.total_space(),
            disk_free: disk.available_space(),
        }
    }).collect::<Vec<_>>();

    Ok(json!(res).into())
}

async fn get_network_info(_req: Request<()>, sys: Arc<Mutex<Networks>>) -> tide::Result {
    let mut net = sys.lock().unwrap();

    net.refresh_list();

    let res = net.list().iter().map(|(name, data)| {
        NetworkInfo {
            network_name: name.to_string(),
            network_data: NetworkTransmit {
                received: data.received(),
                transmitted: data.transmitted(),
                total_received: data.total_received(),
            },
        }
    }).collect::<Vec<_>>();

    Ok(json!(res).into())
}

async fn get_process_info(_req: Request<()>, sys: Arc<Mutex<System>>) -> tide::Result {
    let mut sys = sys.lock().unwrap();

    sys.refresh_processes(ProcessesToUpdate::All);
    sys.refresh_processes_specifics(ProcessesToUpdate::All, sysinfo::ProcessRefreshKind::everything());

    let mut res = vec![];
    for (_, process) in sys.processes() {
        if process.pid() != sysinfo::Pid::from(0) && process.user_id().is_some() {
            let _uid = process.user_id();
            let _gid = process.group_id();

            let uid: String;
            if _uid.is_none() {
                uid = "None".to_string();
            } else {
                uid = _uid.unwrap().to_string();
            }

            let gid: String;
            if _gid.is_none() {
                gid = "None".to_string();
            } else {
                gid = _gid.unwrap().to_string();
            }

            res.push(ProcessInfo {
                process_name: process.name().to_str().unwrap().to_string(),
                process_id: process.pid().as_u32(),
                process_memory: process.memory(),
                process_cpu: process.cpu_usage(),
                process_run_time: process.run_time(),
                process_uid: uid,
                process_gid: gid,
                process_executable: process.exe().is_some().then(|| process.exe().unwrap().to_str().unwrap().to_string()),
                process_parent: process.parent().is_some().then(|| process.parent().unwrap().as_u32()),
                process_thread_kind: if process.thread_kind() == Option::from(sysinfo::ThreadKind::Userland) {
                    "Userland".to_string()
                } else if process.thread_kind() == Option::from(sysinfo::ThreadKind::Kernel) {
                    "Kernel".to_string()
                } else {
                    "Unknown".to_string()
                },
            });
        }
    }

    Ok(json!(res).into())
}

#[derive(Debug, Deserialize)]
struct KillProcess {
    pid: u32,
    signal: String,
}

impl Default for KillProcess {
    fn default() -> Self {
        KillProcess {
            pid: u32::MAX,
            signal: "kill".to_string(),
        }
    }
}

async fn kill_process(req: Request<()>, sys: Arc<Mutex<System>>) -> tide::Result {
    let sys = sys.lock().unwrap();

    let page: KillProcess = req.query()?;

    let match_signal = match page.signal.as_str() {
        "kill" => sysinfo::Signal::Kill,
        "term" => sysinfo::Signal::Term,
        "int" => sysinfo::Signal::Interrupt,
        "quit" => sysinfo::Signal::Quit,
        "stop" => sysinfo::Signal::Stop,
        "cont" => sysinfo::Signal::Continue,
        "hup" => sysinfo::Signal::Hangup,
        "usr1" => sysinfo::Signal::User1,
        "usr2" => sysinfo::Signal::User2,
        _ => sysinfo::Signal::Kill,
    };

    // Convert u32 to Pid (Pid::from(usize))
    let pid = Pid::from(page.pid as usize);
    tide::log::info!("Trying to kill process with PID: {}", pid);

    if let Some(process) = sys.process(pid) {
        process.kill_with(match_signal);
        tide::log::info!("Process with PID: {} killed", pid);
        Ok(json!({ "status": "ok" }).into())
    } else  {
        tide::log::error!("Process {} not found", pid);
        Err(Error::from_str(404, "Process not found"))
    }

}

async fn get_temps_info(_req: Request<()>, sys: Arc<Mutex<Components>>) -> tide::Result {
    let mut prc = sys.lock().unwrap();

    prc.refresh_list();

    let mut res: Vec<TempInfo> = vec![];
    for component in prc.list() {
        let temp = component.temperature();
        let critical = component.critical();
        res.push(TempInfo {
            temp_name: component.label().to_string(),
            temp_value: temp,
            temp_critical: critical,
        });
    }

    Ok(json!(res).into())
}

async fn get_user_info(req: Request<()>, usr: Arc<Mutex<Users>>, grp: Arc<Mutex<Groups>>) -> tide::Result {
    let mut usr = usr.lock().unwrap();
    let mut grp = grp.lock().unwrap();

    let id: String = req.param("id")?.parse().unwrap();
    let uid: Uid = Uid::from_str(&id).unwrap();

    usr.refresh_list();
    let user = usr.get_user_by_id(&uid);

    if user.is_none() {
        return Err(Error::from_str(404, "User not found"));
    }

    grp.refresh_list();
    let group = grp.list().iter().find(|g| g.id() == &user.unwrap().group_id());

    println!("{:?}", user.unwrap());

    Ok(json!({
        "uid": user.unwrap().id().to_string(),
        "gid": group.unwrap().id().to_string(),
        "username": user.unwrap().name().to_string(),
        "groupname": group.unwrap().name().to_string(),
    }).into())
}

async fn shutdown_system(_req: Request<()>) -> tide::Result {
    // Test for OS and shutdown the system
    if System::name().is_some() {
        if System::name().unwrap() == "Windows".to_string() {
            std::process::Command::new("shutdown").arg("/s").arg("/t").arg("0").output().unwrap();
        } else {
            std::process::Command::new("shutdown").arg("-h").arg("now").output().unwrap();
        }
    } else {
        tide::log::error!("OS not found");
        return Err(Error::from_str(404, "OS not found"));
    }

    Ok(json!({ "status": "ok" }).into())
}

async fn restart_system(_req: Request<()>) -> tide::Result {
    // Test for OS and restart the system
    if System::name().is_some() {
        if System::name().unwrap() == "Windows".to_string() {
            std::process::Command::new("shutdown").arg("/r").arg("/t").arg("0").output().unwrap();
        } else {
            std::process::Command::new("shutdown").arg("-r").arg("now").output().unwrap();
        }
    } else {
        tide::log::error!("OS not found");
        return Err(Error::from_str(404, "OS not found"));
    }

    Ok(json!({ "status": "ok" }).into())
}
