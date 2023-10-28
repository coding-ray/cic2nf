use cic2nf::{
    cic::reader::read_ids_csv,
    nf::{categorize_nf, cic_to_nf_batch, write_nf_file, NetFlow},
};
use glob::glob;

fn convert_cic_file_to_nf_files(
    in_path: &String,
    out_dir: &String,
    is_am: &Option<bool>,
    benign_label_name: &String,
) {
    let (cic_records, label_library) = read_ids_csv(in_path, is_am, benign_label_name)
        .expect(&format!("Unable to load {}", in_path).as_str());

    let nf_records: Vec<NetFlow> = cic_to_nf_batch(&cic_records)
        .expect(&format!("Unable to convert CICRecord's in {} to NetFlow's.", out_dir).to_string());

    std::fs::create_dir_all(out_dir)
        .expect(&format!("Unable to create output directory {}", out_dir).to_string());

    let categorized_nf_records: Vec<Vec<NetFlow>> = categorize_nf(nf_records, label_library);

    for nf_one_category in categorized_nf_records {
        if nf_one_category.is_empty() {
            continue;
        }
        let label_name = nf_one_category[0].label().name();
        let out_path: String = format!("{}/{}.nf", out_dir, label_name);
        write_nf_file(&nf_one_category, &out_path);
    }
}

const VALID_OPTIONS: [&'static str; 1] = ["-R"];

fn test_options(options: &Vec<String>) {
    let unknown_options = options
        .into_iter()
        .filter(|a| !VALID_OPTIONS.contains(&&a.as_str()));
    if unknown_options.clone().count() == 0 {
        return;
    }

    let mut output: String = String::from("Unknown option(s): ");
    for option in unknown_options {
        output.push_str(option.as_str());
        output.push_str(", ");
    }

    // remove trailing ", "
    output.pop();
    output.pop();

    panic!("{}", output);
}

fn get_help_message(program_name: &String) -> String {
    const INFO: &'static str =
        "Convert CIC datasets in CSV files to categorized NetFlow v5 files.\n";

    let usage: String = format!(
        "Usage:\n  {} {}",
        program_name, "[-R] <type> <benign_label_name> <out_dir> <in_path> [is_am]",
    );

    let example_single: String = format!(
        "Example (load single csv file):\n  {} {}",
        program_name, "IDS-2017 BENIGN nf-dir input/data.csv y",
    );

    let example_recursive: String = format!(
        "Example (load csv files recursively):\n  {} {}",
        program_name, "-R DDoS-2019 benign out/nf-dir csv-dir",
    );

    return format!(
        "{}\n\n{}\n\n{}\n\n{}\n",
        INFO, usage, example_single, example_recursive
    );
}

fn main() {
    // load command-line arguments
    let args: Vec<String> = std::env::args().collect();

    // extract options
    let options = args
        .clone()
        .into_iter()
        .filter(|a| a.starts_with('-'))
        .collect();

    test_options(&options);

    let mut to_scan_dir: bool = false;
    if options.contains(&String::from("-R")) {
        to_scan_dir = true;
    }

    // extract parameters: <executable> <benign_label_name> <out_dir> <in_path> [is_am]
    let parameters: Vec<String> = args.into_iter().filter(|a| !a.starts_with('-')).collect();
    let p_len = parameters.len();

    if p_len == 1 {
        println!("{}", get_help_message(&parameters[0]));
        return;
    }

    if (p_len != 4) && (p_len != 5) {
        panic!(
            "{}\n\n{}",
            "Error: Incorrect number of parameters.",
            get_help_message(&parameters[0])
        );
    }

    // store parameters
    let dataset_name: String = parameters[1].clone();
    let benign_label_name: String = parameters[2].clone();
    let output_dir: String = parameters[3].clone();
    let mut input_path: String = parameters[4].clone();
    let is_am: Option<bool> = if p_len == 5 {
        None
    } else {
        Some(parameters[5] == "y")
    };

    if dataset_name != "CIC-IDS-2017" {
        todo!();
    }

    // deal with single-csv version
    if !to_scan_dir {
        convert_cic_file_to_nf_files(&input_path, &output_dir, &is_am, &benign_label_name);
        return;
    }

    // deal with multiple-csv version
    println!("Not implemented yet: -R");
    println!("Found CSV files:");
    input_path.push_str("/**/*.csv");
    for entry in glob(input_path.as_str()).expect("Failed to read a glob pattern") {
        match entry {
            Ok(path) => println!("{:?}", path.display()),
            Err(e) => println!("{:?}", e),
        }
    }
    todo!();
}
