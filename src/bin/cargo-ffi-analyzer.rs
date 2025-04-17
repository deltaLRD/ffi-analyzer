use ffi_analyzer::{
    option::AnalysisOption,
    utils::{bb_contains, demangle_name, get_hash},
};
use llvm_ir::{HasDebugLoc, Module};
use llvm_ir_analysis::CrossModuleAnalysis;
use log::{error, info};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    env,
};

struct CallStackNode {
    now: String,
    pre: Option<String>,
}

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
        let mut node_visit = BTreeMap::new();
        let mut sub_dot_str = String::from("");
        info!("ffi:{}", ffi);
        infect_functions.insert(ffi.to_string());
        let ffi_str = get_hash(&ffi);
        sub_dot_str.push_str(&format!(
            "        {} [color=red, label=\"{}\"];\n",
            &format!("FFI{}_Node{}", &ffi_str, &ffi_str),
            ffi
        ));
        let mut queue = VecDeque::new();
        
        queue.push_back(ffi.to_string());
        node_visit.insert(ffi.to_string(), true);
        while !queue.is_empty() {
            let now = queue.pop_front().unwrap();
            if queue.len() > 100 {
                info!("now: {:?}", &now);
                info!("queue: {:#?}", &queue);
                error!("OOM");
                break;
            }
            let now_str = get_hash(&now);
            let nexts = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                call_graph.callers(&now)
            })) {
                Ok(callers) => callers,
                Err(err) => {
                    error!("Error: {:?}", err);
                    continue;
                }
            };
            for next in nexts {
                match node_visit.get(&next.to_string()) {
                    Some(true) => {
                        // info!("! Recursion risk !\n{} -> {}", &next, &now);
                        continue;
                    },
                    _ => {}
                }
                let next_dam_str = demangle_name(&next.to_string());
                let next_str = get_hash(&next);
                match node_visit.get(&next.to_string()) {
                    Some(true) => {},
                    _ => {
                        sub_dot_str.push_str(&format!(
                            "        {} [label=\"{}\"];\n",
                            &format!("FFI{}_Node{}", &ffi_str, &next_str),
                            &next_dam_str
                        ));
                        node_visit.insert(next.to_string(), true);
                    }
                }
                
                sub_dot_str.push_str(&format!(
                    "        {} -> {};\n",
                    &format!("FFI{}_Node{}", &ffi_str, &next_str),
                    &format!("FFI{}_Node{}", &ffi_str, &now_str)
                ));
                infect_functions.insert(next.to_string());
                queue.push_back(next.to_string());
            }
        }
        dot_str.push_str(&format!("    subgraph FFI{} {{\n", &ffi_str));
        dot_str.push_str(&format!("        style=filled;\n"));
        dot_str.push_str(&format!("        color=lightgrey;\n"));
        dot_str.push_str(&format!("        label=\"{}\";\n", &ffi));
        dot_str.push_str(&format!("        rankdir=LR;\n"));
        dot_str.push_str(&format!("{}\n", &sub_dot_str));
        dot_str.push_str(&format!("    }}\n"));
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
            let mut function_contain_ffi = false;
            let contain_ffi = bb_contains(bb, &infect_functions);
            if contain_ffi {
                ffi_bb_cnt += 1;
                function_contain_ffi = true;
                // info!("function: {:?} bb:{:#?}", &demangle_name(&function_name), &bb.instrs.iter().map(|x| x.to_string()).collect::<Vec<_>>());
                sub_graph.push_str(&format!("        {} [label=\"{}\", color=red];\n", entry_str, function_label));
            } else {
                sub_graph.push_str(&format!("        {} [label=\"{}\"];\n", entry_str, function_label));
            }
            // sub_graph.push_str(&format!("        {} [label=\"{}\"];\n", entry_str, entry));

            while !queue.is_empty() {
                let now = queue.pop_front().unwrap();
                if queue.len() > 100 {
                    error!("CFG OOM:");
                    info!("now: {:?}", &now);
                    info!("queue: {:#?}", &queue);
                    error!("OOM");
                    break;
                }
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
                                    function_contain_ffi = true;
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
            if !function_contain_ffi {
                continue;
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

    info!("Start Src Level Analyzer");
    let mut interface_str = String::from("");
    let functions = analyzer.functions();
    let mut function_map = BTreeMap::new();

    for function in functions {
        let function_name = function.name.clone();
        let mut bb_map = BTreeMap::new();
        for bb in &function.basic_blocks {
            let bb_name = bb.name.clone();
            bb_map.insert(bb_name, bb.clone());
        }
        function_map.insert(function_name, (function.clone(), bb_map.clone()));
    }

    // let mut file = std::fs::File::create("interface.txt").unwrap();
    // std::io::Write::write_all(&mut file, interface_str.as_bytes()).unwrap();
    for ffi in &options.ffi_functions {
        // file.write(format!("ffi:{}\n", ffi).as_bytes()).unwrap();
        // let mut chain_cnt = 0;
        
        interface_str.push_str(&format!("ffi:{}\n", ffi));
        let mut call_heads: BTreeSet<String> = BTreeSet::new();
        let mut final_heads: BTreeSet<String> = BTreeSet::new();
        let mut chain: BTreeMap<String, String> = BTreeMap::new();
        let mut next_heads: BTreeSet<String> = BTreeSet::new();

        call_heads.insert(ffi.to_string());
        while !call_heads.is_empty() {
            
            for head in call_heads.clone() {
                let nexts = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    call_graph.callers(&head)
                })) {
                    Ok(callers) => callers,
                    Err(_) => {
                        final_heads.insert(head.clone());
                        continue;
                    }
                };
                let mut len = 0;
                for next in nexts {
                    len = len + 1;
                    chain.insert(next.to_string().clone(), head.clone());
                    next_heads.insert(next.to_string());
                }
                if len == 0 {
                    final_heads.insert(head.clone());
                }
            }
            if call_heads.len() > 100 {
                info!("call_heads: {:#?}", &call_heads);
                info!("next_heads: {:#?}", &next_heads);
                error!("OOM");
                break;
            }
            call_heads = next_heads.clone();
            next_heads.clear();
        }
        // info!("call_heads: {:#?}", call_heads);
        // info!("final_heads: {:#?}", final_heads);
        // info!("chain: {:#?}", chain);
        for (idx, head) in final_heads.iter().enumerate() {
            
            let mut now = head.clone();
            let mut next = chain.get(&now);
            let mut result = Vec::new();
            while next.is_some() {
                let now_func = function_map.get(&now);
                match now_func {
                    Some((function, _)) => match function.get_debug_loc() {
                        Some(debug_location) => {
                            let debug_location = debug_location.clone();
                            let file = debug_location.filename.clone();
                            let line = debug_location.line;
                            let column = debug_location.col;
                            let debug_info = format!(
                                "Function: {:?} file: {:?} line: {:?} column: {:?}",
                                demangle_name(&now), &file, &line, &column
                            );
                            result.push(debug_info);
                        }
                        None => {
                            error!("Function not found: {}", now);
                            continue;
                        }
                    },
                    None => {
                        error!("Function not found: {}", now);
                        continue;
                    }
                }
                let next_str = next.unwrap();
                let (_, bb_map) = match function_map.get(&now) {
                    Some(function) => function,
                    None => {
                        error!("Function not found: {}", now);
                        break;
                    }
                };
                bb_map.iter().for_each(|(_bb_name, bb)| {
                    for inst in &bb.instrs {
                        match inst {
                            llvm_ir::Instruction::Call(call) => {
                                let call_function = &call.function;
                                if call_function.is_right() {
                                    let call_function = call_function.clone().right().unwrap();
                                    match call_function {
                                        llvm_ir::Operand::ConstantOperand(const_ref) => {
                                            match const_ref.as_ref() {
                                                llvm_ir::Constant::GlobalReference {
                                                    name,
                                                    ty: _,
                                                } => {
                                                    let name = name.to_string().chars().skip(1).collect::<String>();
                                                    if name.eq(&next_str.clone()) {
                                                        let debug_location = inst.get_debug_loc();
                                                        match debug_location {
                                                            Some(debug_info) => {
                                                                let file = debug_info.filename.clone();
                                                                let line = debug_info.line;
                                                                let column = debug_info.col;
                                                                let debug_info = format!(
                                                                    "Function: {:?} file: {:?} line: {:?} column: {:?}",
                                                                    demangle_name(&now), &file, &line, &column
                                                                );
                                                                result.push(debug_info);
                                                            },
                                                            None => {
                                                                result.push("Unknown".to_string());
                                                            },
                                                        }
                                                    } else {
                                                        continue;
                                                    }
                                                }
                                                _ => {}
                                            }
                                        }
                                        llvm_ir::Operand::LocalOperand { name, ty: _ } => {
                                            if name.to_string().chars().skip(1).collect::<String>().eq(&next_str.clone()) {
                                                let debug_location = inst.get_debug_loc();
                                                match debug_location {
                                                    Some(debug_info) => {
                                                        let file = debug_info.filename.clone();
                                                        let line = debug_info.line;
                                                        let column = debug_info.col;
                                                        let debug_info = format!(
                                                            "Function: {:?} file: {:?} line: {:?} column: {:?}",
                                                            &now, &file, &line, &column
                                                        );
                                                        result.push(debug_info);
                                                    },
                                                    None => {
                                                        result.push("Unknown".to_string());
                                                    },
                                                }
                                            } else {
                                                continue;
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                });
                now = next_str.to_string();
                next = chain.get(&now);
            }
            
            if result.is_empty() {
                interface_str.push_str(&format!("None\n"));
                interface_str.push_str("--------\n\n");
                continue;
            }
            interface_str.push_str(&format!("chain: {}\n", idx));
            for debug_info in result {
                interface_str.push_str(&format!("{}\n", debug_info));
            }
            interface_str.push_str("--------\n\n");
        }

    }
    
    info!("End Src Level Analyzer");
}
