use ffi_analyzer::{option::AnalysisOption, utils::{bb_contains, demangle_name, get_hash}};
use llvm_ir::Module;
use llvm_ir_analysis::CrossModuleAnalysis;
use log::{error, info};
use std::{collections::{BTreeMap, BTreeSet, VecDeque}, env};
fn main() {
    unsafe {
        std::env::set_var("RUST_LOG", "info");
        std::env::set_var("RUST_BACKTRACE", "1");
    }
    // Initialize logger
    pretty_env_logger::init_timed();
    info!("Start anlayzer");
    let options = AnalysisOption::from_args(env::args());
    let mut modules = Vec::new();
    for ir in options.bitcode_paths {
        info!("bc_path: {}", &ir);
        let module = Module::from_bc_path(ir).unwrap();
        modules.push(module.clone());
    }
    let analyzer = CrossModuleAnalysis::new(&modules);
    let call_graph = analyzer.call_graph();
    
    let mut dot_str = String::from("");
    let ffi_cnt = &options.ffi_functions.len();
    let mut infect_functions = BTreeSet::new();
    for ffi in &options.ffi_functions {
        info!("ffi:{}", ffi);
        infect_functions.insert(ffi.to_string());
        let ffi_digest = md5::compute(ffi.as_bytes());
        dot_str.push_str(&format!("    {} [color=red, label=\"{}\"];\n", &format!("Node{:x}", ffi_digest), ffi));
        let mut queue = VecDeque::new();
        let mut visit = BTreeMap::new();
        queue.push_back(ffi.to_string());
        visit.insert(ffi.to_string(), true);
        while !queue.is_empty() {
            let now = queue.pop_front().unwrap();
            // if queue.len() > 1000 {
            //     error!("OOM");
            //     break;
            // }
            // let now_str = demangle_name(&now);
            let now_str = &now;
            let now_digest = md5::compute(now_str.as_bytes());
            let nexts = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| call_graph.callers(&now))) {
                Ok(callers) => callers,
                Err(err) => {
                    error!("Error: {:?}", err);
                    continue;
                }
            };
            for next in nexts {
                match visit.get(&next.to_string()) {
                    Some(true) => {
                        continue;
                    },
                    _ => {}
                }
                let next_dam_str = demangle_name(&next.to_string());
                let next_str = &next.to_string();
                let next_digest = md5::compute(next_str.as_bytes());

                dot_str.push_str(&format!("    {} [label=\"{}\"];\n", &format!("Node{:x}", next_digest), &next_dam_str));
                dot_str.push_str(&format!("    {} -> {};\n", &format!("Node{:x}", next_digest), &format!("Node{:x}", now_digest)));
                infect_functions.insert(next_dam_str);
                queue.push_back(next.to_string());
            }
        }
    }
    
    let dot_str = format!("digraph G {{\n    rankdir=LR;\n{}\n}}", dot_str);
    let mut file = std::fs::File::create("call_graph.dot").unwrap();
    std::io::Write::write_all(&mut file, dot_str.as_bytes()).unwrap();
    
    // control flow graph
    info!("Start control flow graph");
    let mut dot_str = String::from("");
    let mut ffi_bb_cnt = 0;
    let mut function_cnt = 0;
    for module in analyzer.modules() {
        let module_name = module.name.clone();
        let module_anlaysis = analyzer.module_analysis(&module_name);
        for function in module.functions.clone() {
            function_cnt += 1;
            let function_name = &function.name;
            // let function_digest = md5::compute(function_name.as_bytes());
            let function_str = format!("Node{}", get_hash(&function_name));

            let function_alaysis = module_anlaysis.fn_analysis(&function_name);
            let control_flow_graph = function_alaysis.control_flow_graph();

            let function_label = demangle_name(&function_name);

            let entry = control_flow_graph.entry();
            let entry_str = format!("{}_BB{}", &function_str, get_hash(&entry));

            let mut queue = VecDeque::new();
            let mut visit = BTreeMap::new();
            queue.push_back(entry);
            // visit.insert(entry, true);

            let mut sub_graph = String::from("");
            let bb = function.get_bb_by_name(&entry).unwrap();
            let contain_ffi = bb_contains(bb, &infect_functions);
            if contain_ffi {
                ffi_bb_cnt += 1;
                // info!("function: {:?} bb:{:#?}", &demangle_name(&function_name), &bb.instrs.iter().map(|x| x.to_string()).collect::<Vec<_>>());
                sub_graph.push_str(&format!("        {} [label=\"{}\", color=red];\n", entry_str, function_label));
            } else {
                sub_graph.push_str(&format!("        {} [label=\"{}\"];\n", entry_str, function_label));
            }
            // sub_graph.push_str(&format!("        {} [label=\"{}\"];\n", entry_str, entry));

            while !queue.is_empty() {
                let now = queue.pop_front().unwrap();
                // if queue.len() > 1000 {
                //     error!("OOM");
                //     break;
                // }
                let now_str = format!("{}_BB{}", &function_str, get_hash(&now));
                let nexts = control_flow_graph.succs(&now);
                for next in nexts {
                    match next {
                        llvm_ir_analysis::CFGNode::Block(next) => {
                            let next_str = format!("{}_BB{}", &function_str, get_hash(&next));
                            if visit.get(&(now.to_string(), next.to_string())).is_none() {
                                let next_label = &demangle_name(&format!("{}",&next).chars().skip(1).collect::<String>());
                                let bb = function.get_bb_by_name(&next).unwrap();
                                let contain_ffi = bb_contains(bb, &infect_functions);
                                if contain_ffi {
                                    ffi_bb_cnt += 1;
                                    // info!("function: {:?} bb:{:#?}", &demangle_name(&function_name), &bb.instrs.iter().map(|x| x.to_string()).collect::<Vec<_>>());
                                    sub_graph.push_str(&format!("        {} [label=\"{}\", color=red];\n", &next_str, &next_label));
                                } else {
                                    sub_graph.push_str(&format!("        {} [label=\"{}\"];\n", &next_str, &next_label));
                                }
                                // sub_graph.push_str(&format!("        {} [label=\"{}\"];\n", &next_str, &next_label));
                                sub_graph.push_str(&format!("        {} -> {};\n", &now_str, &next_str));
                                queue.push_back(next);
                                let now_str_tmp = now.to_string();
                                let next_str_tmp = next.to_string();
                                visit.insert((now_str_tmp, next_str_tmp), true);
                            }
                        },
                        llvm_ir_analysis::CFGNode::Return => {
                            let next_str = format!("{}_BB{}", &function_str, get_hash(&format!("Return")));
                            if visit.get(&(now.to_string(), next.to_string())).is_none() {
                                sub_graph.push_str(&format!("        {} [label=\"{}\"];\n", &next_str, &demangle_name(&format!("{}",&next)) ));
                                sub_graph.push_str(&format!("        {} -> {};\n", &now_str, &next_str));
                                visit.insert((now.to_string(), next.to_string()), true);
                            }
                        },
                    }
                
                }
            }
            
            dot_str.push_str(&format!("    subgraph {} {{\n", &function_str));
            dot_str.push_str(&format!("        style=filled;\n"));
            dot_str.push_str(&format!("        color=lightgrey;\n"));
            dot_str.push_str(&format!("        label=\"{}\";\n", &demangle_name(&function_name)));
            dot_str.push_str(&format!("        rankdir=TB;\n"));
            dot_str.push_str(&format!("{}\n", &sub_graph));
            dot_str.push_str(&format!("    }}\n"));
        }
    }
    let dot_str = format!("digraph G {{\n    rankdir=LR;\n{}\n}}", dot_str);

    let mut file = std::fs::File::create("control_flow_graph.dot").unwrap();
    std::io::Write::write_all(&mut file, dot_str.as_bytes()).unwrap();
    info!("End analyzer");
    info!("FFI BB count: {}", ffi_bb_cnt);
    info!("Function count: {}", function_cnt);
    info!("FFI function count: {}", ffi_cnt);
}
