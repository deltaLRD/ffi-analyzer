use std::{env::Args, fs::File, io::BufRead, path::Path};

use log::info;


pub struct AnalysisOption {
    pub ffi_functions: Vec<String>,
    pub bitcode_paths: Vec<String>,
}

impl Default for AnalysisOption {
    fn default() -> Self {
        let mut ffi_functions = vec![];
        let mut bitcode_paths = vec![];
        info!("Start init Analyzer Option");

        let entry_points_path = Path::new("./target/entry_points");
        info!("Entry points path: {:?}", entry_points_path.canonicalize().unwrap());
        let dir = std::fs::read_dir(entry_points_path).unwrap();
        for entry in dir {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                let file = std::fs::File::open(entry.path()).unwrap();
                for line in std::io::BufReader::new(file).lines() {
                    if let Ok(line_str) = line {
                        if line_str.starts_with("FFI: ") {
                            ffi_functions.push(line_str.chars().skip(5).collect())
                        }
                    }
                }
            }
        }

        let file = File::open(Path::new("target").join("bitcode_paths")).unwrap();
        for line in std::io::BufReader::new(file).lines() {
            if let Ok(line_str) = line {
                bitcode_paths.push(line_str);
            }
        }

        info!("FFI functions: {:?}", ffi_functions);
        info!("Bitcode paths: {:?}", bitcode_paths);

        Self {
            ffi_functions,
            bitcode_paths,
        }
    }
}

impl AnalysisOption {
    pub fn from_args(args: Args) -> Self {
        let args = args.enumerate().map(|( _i, arg)| arg).collect::<Vec<_>>();
        let mut res = Self::default();
        for (i, arg) in args.iter().enumerate() {
            if arg.starts_with("--") {
                match &arg[2..] {
                    "bitcode" => {
                        res.bitcode_paths.push(args[i+1].clone());
                    }
                    _ => {}
                }
            }
        }
        res
    }
}