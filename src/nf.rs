use crate::cic::{CICRecord, FlowTimeStamp, Label};
use chrono::Duration;
use std::{
    cmp::max,
    collections::HashMap,
    fs::File,
    io::{BufWriter, Write},
};

#[derive(Copy, Clone, Debug)]
pub struct Flags {
    cwr: bool,
    ece: bool,
    urg: bool,
    ack: bool,
    psh: bool,
    rst: bool,
    syn: bool,
    fin: bool,
}

impl Flags {
    fn new() -> Flags {
        Flags {
            cwr: false,
            ece: false,
            urg: false,
            ack: false,
            psh: false,
            rst: false,
            syn: false,
            fin: false,
        }
    }
}

impl std::fmt::Display for Flags {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let c: &'static str = if self.cwr { "C" } else { "." };
        let e: &'static str = if self.ece { "E" } else { "." };
        let u: &'static str = if self.urg { "U" } else { "." };
        let a: &'static str = if self.ack { "A" } else { "." };
        let p: &'static str = if self.psh { "P" } else { "." };
        let r: &'static str = if self.rst { "R" } else { "." };
        let s: &'static str = if self.syn { "S" } else { "." };
        let f: &'static str = if self.fin { "F" } else { "." };
        write!(formatter, "{}{}{}{}{}{}{}{}", c, e, u, a, p, r, s, f)
    }
}

#[derive(Clone, Debug)]
pub struct NetFlow {
    timestamp: FlowTimeStamp,
    duration: Duration,
    duration_str_width: u8,
    protocol: u8,
    src_ip: String,
    src_port: u32,
    dst_ip: String,
    dst_port: u32,
    flags: Flags,
    qos: f32,
    n_packet: u32,
    n_bytes_packet: u32,
    n_flow: u32,
    label: Label,
}

const DURATION_ZERO: Duration = Duration::zero();
const DURATION_MINUS_ONE_NS: Duration = Duration::microseconds(-1);

impl NetFlow {
    pub fn new(cr: &crate::cic::CICRecord) -> (NetFlow, NetFlow) {
        let timestamp: FlowTimeStamp = *cr.timestamp();
        let mut duration: Duration = *cr.duration();
        if duration == DURATION_MINUS_ONE_NS {
            println!("Warning: duration of -1 us; convert it to 0.");
            duration = DURATION_ZERO;
        }
        if duration < DURATION_ZERO {
            println!("Warning: duration less than -1 us; convert it to 0.");
            println!("Duration: {} us", duration.num_microseconds().unwrap());
            dbg!(cr);
            duration = DURATION_ZERO;
        }
        let protocol: u8 = *cr.protocol();
        let src_ip: &String = cr.src_ip();
        let src_port: u32 = *cr.src_port();
        let dst_ip: &String = cr.dst_ip();
        let dst_port: u32 = *cr.dst_port();
        let n_packet: &[i32; 2] = cr.n_packet();
        let n_bytes_packet: &[i32; 2] = cr.n_bytes_packet();
        let label: &Label = cr.label();
        let nf1: NetFlow = NetFlow {
            timestamp,
            duration,
            duration_str_width: 0,
            protocol,
            src_ip: src_ip.clone(),
            src_port,
            dst_ip: dst_ip.clone(),
            dst_port,
            flags: Flags::new(),
            qos: 0.0,
            n_packet: n_packet[0] as u32,
            n_bytes_packet: n_bytes_packet[0] as u32,
            n_flow: 1,
            label: label.clone(),
        };
        let nf2: NetFlow = NetFlow {
            timestamp,
            duration,
            duration_str_width: 0,
            protocol,
            src_ip: dst_ip.clone(),
            src_port: dst_port,
            dst_ip: src_ip.clone(),
            dst_port: src_port,
            flags: Flags::new(),
            qos: 0.0,
            n_packet: n_packet[1] as u32,
            n_bytes_packet: n_bytes_packet[1] as u32,
            n_flow: 1,
            label: label.clone(),
        };
        return (nf1, nf2);
    }

    pub fn duration_ms(&self) -> i64 {
        return self.duration.num_milliseconds();
    }

    pub fn duration_str_width_mut(&mut self) -> &mut u8 {
        &mut self.duration_str_width
    }

    pub fn label(&self) -> &Label {
        return &self.label;
    }

    pub fn format_duration(&self) -> String {
        let ms: i64 = self.duration_ms();
        let s: i64 = ms / 1000;
        let ms: i64 = ms % 1000;
        let tmp: String = format!("{}.{}", s, ms);
        return format!("{tmp:>w$}", w = self.duration_str_width as usize);
    }
}

impl std::fmt::Display for NetFlow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} {} {:>3} {:>15}:{:<5} ->   {:>15}:{:<5} {:>3} {:<8} {:>8} {:>8} {:>5}",
            self.timestamp,
            self.format_duration(),
            self.protocol,
            self.src_ip,
            self.src_port,
            self.dst_ip,
            self.dst_port,
            self.qos,
            self.flags,
            self.n_packet,
            self.n_bytes_packet,
            self.n_flow
        )
    }
}

fn get_n_digit_in_decimal(mut x: i64) -> u8 {
    if x == 0 {
        return 1;
    }

    let mut n: u8 = 0;
    while x != 0 {
        x /= 10;
        n += 1;
    }

    return n;
}

pub fn cic_to_nf_batch(cic_records: &Vec<CICRecord>) -> std::io::Result<Vec<NetFlow>> {
    let mut netflow_storage: Vec<NetFlow> = Vec::new();
    let mut max_duration_ms: i64 = 0;
    for r in cic_records {
        let (nf1, nf2) = NetFlow::new(r);
        max_duration_ms = max(max_duration_ms, nf1.duration_ms());
        max_duration_ms = max(max_duration_ms, nf2.duration_ms());
        netflow_storage.push(nf1);
        netflow_storage.push(nf2);
    }

    let mut duration_width = get_n_digit_in_decimal(max_duration_ms) + 1;
    if max_duration_ms < 1000 {
        duration_width += 1;
    };

    for n in &mut netflow_storage {
        *n.duration_str_width_mut() = duration_width;
    }
    return Ok(netflow_storage);
}

pub fn write_nf_file(nf_records: &Vec<NetFlow>, fname: &String) {
    // FIXME: toggle this function with command-line flags
    /*if Path::new(fname).exists() {
        print!("File {} exists. Do you want to overwrite it? [Y/n] ", fname);
        let mut buffer = String::new();
        stdin()
            .read_line(&mut buffer)
            .expect("Error: Cannot read from stdin.");
        if buffer == "n" {
            println!("Skipped file: {}", fname);
            return;
        }
    }*/
    let of = File::create(fname.to_string())
        .expect(&format!("Unable to create/edit file {}", fname).to_string());

    let mut ob = BufWriter::new(of);

    for line in nf_records {
        writeln!(ob, "{}", line).expect(
            &format!(
                "Unable to write the following content to file {}\n{}",
                fname, line
            )
            .to_string(),
        );
    }
}

pub fn categorize_nf(
    nf_records: Vec<NetFlow>,
    label_library: HashMap<String, u8>,
) -> Vec<Vec<NetFlow>> {
    // categorized_records[0] is benign
    let mut categorized_records: Vec<Vec<NetFlow>> =
        vec![Vec::<NetFlow>::new(); label_library.len()];

    for nf in nf_records {
        let i = (nf.label.index() - 1) as usize;
        categorized_records[i].push(nf);
    }

    return categorized_records;
}
