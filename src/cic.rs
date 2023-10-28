use chrono::{Duration, NaiveDateTime};

#[derive(Clone, Copy, Debug)]
pub struct FlowTimeStamp {
    time: NaiveDateTime,
}

impl std::fmt::Display for FlowTimeStamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.time.format("%Y-%m-%d %H:%M:%S%.3f"))
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Label {
    index: u8, // 0 for no index, 1 for benign
    name: String,
}

impl Label {
    pub fn index(&self) -> u8 {
        return self.index;
    }

    pub fn index_mut(&mut self) -> &mut u8 {
        &mut self.index
    }

    pub fn name(&self) -> &String {
        &self.name
    }
}

/*
 * A record (row) in the datasets of the CIC in CSV format.
 * For each array-type field, field[0] is forward and
 * field[1] is backward.
 */
#[derive(Clone, Debug)]
pub struct CICRecord {
    src_ip: String,
    src_port: u32,
    dst_ip: String,
    dst_port: u32,
    protocol: u8,
    timestamp: FlowTimeStamp,
    duration: Duration,
    n_packet: [i32; 2],
    n_bytes_packet: [i32; 2],
    label: Label,
}

impl CICRecord {
    pub fn from_ids_csv(
        record: &csv::StringRecord,
        is_am: &Option<bool>,
        guessed_time_format_index: usize,
    ) -> (CICRecord, usize) {
        let (timestamp, actual_time_format_index) =
            CICRecord::str_to_timestamp(record[6].trim(), is_am, guessed_time_format_index);

        let cic_record: CICRecord = CICRecord {
            src_ip: String::from(record[1].trim()),
            src_port: record[2].parse().unwrap(),
            dst_ip: String::from(record[3].trim()),
            dst_port: record[4].parse().unwrap(),
            protocol: record[5].parse().unwrap(),
            timestamp,
            duration: Duration::microseconds(record[7].parse().unwrap()),
            n_packet: [
                Self::str_sum_i32(&record[8], &record[40]),
                Self::str_sum_i32(&record[9], &record[41]),
            ],
            n_bytes_packet: [
                record[10].parse::<f32>().unwrap() as i32,
                record[11].parse::<f32>().unwrap() as i32,
            ],
            label: Label {
                index: 0,
                name: String::from(record[84].trim()),
            },
        };

        (cic_record, actual_time_format_index)
    }

    const TIME_FORMATS: [&'static str; 6] = [
        "%d/%m/%Y %I:%M %P",        // 11:09 pm
        "%d/%m/%Y %I:%M:%S %P",     // 11:09:09 pm
        "%d/%m/%Y %I:%M:%S%.6f %P", // 11:09:09.000009 pm
        "%d/%m/%Y %H:%M",           // 23:09
        "%d/%m/%Y %H:%M:%S",        // 23:09:09
        "%d/%m/%Y %H:%M:%S%.6f",    // 23:09:09.000009
    ];

    /**
    Convert string (str) to Timestamp, and along with the
    actual time format index.

    If you deal with multiple records in the same file,
    it is recommended to feed the actual index back as
    the next guessed index.
    */
    fn str_to_timestamp(
        cic_timestamp_str: &str,
        is_am: &Option<bool>,
        guessed_time_format_index: usize,
    ) -> (FlowTimeStamp, usize) {
        let guess_i: usize = guessed_time_format_index;

        let mut time_str: String = cic_timestamp_str.to_owned();
        match is_am {
            Some(true) => time_str += " am",
            Some(false) => time_str += " pm",
            None => {}
        }

        let time_str: &str = time_str.as_str();
        if let Ok(time) = NaiveDateTime::parse_from_str(time_str, Self::TIME_FORMATS[guess_i]) {
            return (FlowTimeStamp { time }, guess_i);
        }

        for i in 0..Self::TIME_FORMATS.len() {
            if i == guess_i {
                continue;
            }
            if let Ok(time) = NaiveDateTime::parse_from_str(time_str, Self::TIME_FORMATS[i]) {
                return (FlowTimeStamp { time }, i);
            }
        }

        panic!(
            "Time string is not in the list of known formats:\n  {}\n",
            time_str
        );
    }

    fn str_sum_i32(s1: &str, s2: &str) -> i32 {
        let i1: i32 = s1.parse::<f32>().unwrap() as i32;
        let i2: i32 = s2.parse::<f32>().unwrap() as i32;
        i1 + i2
    }

    pub fn src_ip(&self) -> &String {
        &self.src_ip
    }

    pub fn src_port(&self) -> &u32 {
        &self.src_port
    }

    pub fn dst_ip(&self) -> &String {
        &self.dst_ip
    }

    pub fn dst_port(&self) -> &u32 {
        &self.dst_port
    }

    pub fn protocol(&self) -> &u8 {
        &self.protocol
    }

    pub fn timestamp(&self) -> &FlowTimeStamp {
        &self.timestamp
    }

    pub fn duration(&self) -> &Duration {
        &self.duration
    }

    pub fn n_packet(&self) -> &[i32; 2] {
        &self.n_packet
    }

    pub fn n_bytes_packet(&self) -> &[i32; 2] {
        &self.n_bytes_packet
    }

    pub fn label(&self) -> &Label {
        &self.label
    }

    pub fn label_mut(&mut self) -> &mut Label {
        &mut self.label
    }
}

pub mod reader {
    use super::CICRecord;

    use csv::{Reader, ReaderBuilder};
    use std::collections::HashMap;
    use std::fs::File;

    pub fn read_ids_csv(
        path_string: &String,
        is_am: &Option<bool>,
        benign_label_name: &String,
    ) -> std::io::Result<(Vec<CICRecord>, HashMap<String, u8>)> {
        let mut csv_reader: Reader<File> = ReaderBuilder::new()
            .has_headers(true)
            .from_path(path_string)
            .expect(&format!("Unable to read CSV file: {}", path_string).as_str());

        let benign_label: (String, u8) = (benign_label_name.clone(), 1);
        let mut label_map: HashMap<String, u8> = HashMap::from([benign_label]);
        let mut cic_record_storage: Vec<CICRecord> = Vec::new();
        let mut cic_record: CICRecord;
        let mut time_format_index: usize = 0;
        for record in csv_reader.records() {
            let str_record: csv::StringRecord = record?;
            if str_record.len() != 85 {
                println!("Warning: Skipped CSV record: {:?}", str_record);
                continue;
            }
            (cic_record, time_format_index) =
                CICRecord::from_ids_csv(&str_record, is_am, time_format_index);
            update_label_and_index_mut(&mut label_map, &mut cic_record);
            cic_record_storage.push(cic_record);
        }

        return Ok((cic_record_storage, label_map));
    }

    fn update_label_and_index_mut(label_map: &mut HashMap<String, u8>, cic_record: &mut CICRecord) {
        let current_label: &String = &cic_record.label().name();
        match label_map.get(current_label) {
            Some(index) => *cic_record.label_mut().index_mut() = *index,
            None => {
                let current_index: u8 = (label_map.len() + 1) as u8;
                label_map.insert(current_label.clone(), current_index);
                *cic_record.label_mut().index_mut() = current_index;
            }
        }
    }
}
