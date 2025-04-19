use ffi_analyzer::{
    option::AnalysisOption,
    utils::{bb_contains, demangle_name, get_hash, CallStackInfo},
};
use llvm_ir::{HasDebugLoc, Module};
use llvm_ir_analysis::CrossModuleAnalysis;
use log::{error, info};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    env,
};

fn main() {
    std::env::set_var("RUST_LOG", "info");
    std::env::set_var("RUST_BACKTRACE", "1");

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
                        continue;
                    }
                    _ => {}
                }
                let next_dam_str = demangle_name(&next.to_string());
                let next_str = get_hash(&next);
                match node_visit.get(&next.to_string()) {
                    Some(true) => {}
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
                sub_graph.push_str(&format!(
                    "        {} [label=\"{}\", color=red];\n",
                    entry_str, function_label
                ));
            } else {
                sub_graph.push_str(&format!(
                    "        {} [label=\"{}\"];\n",
                    entry_str, function_label
                ));
            }

            while !queue.is_empty() {
                let now = queue.pop_front().unwrap();
                if queue.len() > 1000 {
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
                                let next_label = &demangle_name(
                                    &format!("{}", &next).chars().skip(1).collect::<String>(),
                                );
                                let bb = function.get_bb_by_name(&next).unwrap();
                                let contain_ffi = bb_contains(bb, &infect_functions);
                                if contain_ffi {
                                    function_contain_ffi = true;
                                    ffi_bb_cnt += 1;
                                    sub_graph.push_str(&format!(
                                        "        {} [label=\"{}\", color=red];\n",
                                        &next_str, &next_label
                                    ));
                                } else {
                                    sub_graph.push_str(&format!(
                                        "        {} [label=\"{}\"];\n",
                                        &next_str, &next_label
                                    ));
                                }
                                sub_graph
                                    .push_str(&format!("        {} -> {};\n", &now_str, &next_str));
                                queue.push_back(next);
                                let now_str_tmp = now.to_string();
                                let next_str_tmp = next.to_string();
                                visit.insert((now_str_tmp, next_str_tmp), true);
                            }
                        }
                        llvm_ir_analysis::CFGNode::Return => {
                            let next_str =
                                format!("{}_BB{}", &function_str, get_hash(&format!("Return")));
                            if visit.get(&(now.to_string(), next.to_string())).is_none() {
                                sub_graph.push_str(&format!(
                                    "        {} [label=\"{}\"];\n",
                                    &next_str,
                                    &demangle_name(&format!("{}", &next))
                                ));
                                sub_graph
                                    .push_str(&format!("        {} -> {};\n", &now_str, &next_str));
                                visit.insert((now.to_string(), next.to_string()), true);
                            }
                        }
                    }
                }
            }
            if !function_contain_ffi {
                continue;
            }
            dot_str.push_str(&format!("    subgraph {} {{\n", &function_str));
            dot_str.push_str(&format!("        style=filled;\n"));
            dot_str.push_str(&format!("        color=lightgrey;\n"));
            dot_str.push_str(&format!(
                "        label=\"{}\";\n",
                &demangle_name(&function_name)
            ));
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

    let mut interfaces = Vec::new();
    for ffi in &options.ffi_functions {
        let mut queue: VecDeque<(String, Vec<String>)> = VecDeque::new();
        let mut visit = BTreeMap::new();
        let mut interface = CallStackInfo {
            ffi_name: ffi.to_string(),
            call_stack: vec![],
        };
        queue.push_back((ffi.to_string(), vec![]));
        visit.insert(
            format!(
                "Function:{} File:{} Line:{}, Column:{}",
                ffi.to_string(),
                "",
                "",
                ""
            )
            .to_string(),
            true,
        );

        while !queue.is_empty() {
            let (now, mut path) = queue.pop_front().unwrap();
            if queue.len() > 10000 {
                info!("now: {:?}", &now);
                // log the queue of first 10 and last 10
                info!("queue: {:#?}", &queue.iter().take(10).collect::<Vec<_>>());
                info!("queue: {:#?}", &queue.iter().rev().take(10).collect::<Vec<_>>());
                error!("OOM");
                break;
            }
            // let demangle_now_str = demangle_name(&now);
            let nexts = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                call_graph.callers(&now)
            })) {
                Ok(callers) => callers,
                Err(_) => {
                    error!("Error: {:?}", now);
                    return ();
                }
            };
            let nexts: Vec<&str> = nexts.collect();
            if nexts.len() == 0 {
                // add call stack to file
                path.reverse();
                interface.call_stack.push(path.clone());
                continue;
            }
            for next in nexts {
                let demangle_next_str = demangle_name(&next.to_string());
                let bb_map = match function_map.get(&next.to_string()) {
                    Some(function) => &function.1,
                    None => {
                        error!("Function not found: {}", now);
                        continue;
                    }
                };
                for bb in bb_map.values() {
                    for inst in &bb.instrs {
                        match inst {
                            llvm_ir::Instruction::Call(call) => {
                                let call_function = &call.function;
                                if call_function.is_left() {
                                    continue;
                                }
                                let call_function = call_function.clone().right().unwrap();
                                match call_function {
                                    llvm_ir::Operand::ConstantOperand(const_ref) => {
                                        match const_ref.as_ref() {
                                            llvm_ir::Constant::GlobalReference { name, ty: _ } => {
                                                let name = name
                                                    .to_string()
                                                    .chars()
                                                    .skip(1)
                                                    .collect::<String>();
                                                if !name.eq(&now) {
                                                    continue;
                                                }
                                                let debug_location = inst.get_debug_loc();
                                                match debug_location {
                                                    Some(debug_info) => {
                                                        let file = debug_info.filename.clone();
                                                        let line = debug_info.line;
                                                        let column = debug_info.col;

                                                        let debug_info = format!(
                                                            "Function: {:?} file: {:?} line: {:?} column: {:?}",
                                                            demangle_next_str, &file, &line, &column
                                                        );

                                                        let key = format!(
                                                            "Function:{} File:{} Line:{}, Column:{}",
                                                            next, &file, &line, &column.unwrap_or(0).to_string()
                                                        );

                                                        if visit.get(&key).is_none() {
                                                            visit.insert(key.clone(), true);
                                                            let mut path_next = path.clone();
                                                            path_next.push(debug_info);

                                                            queue.push_back((
                                                                next.to_string(),
                                                                path_next,
                                                            ));
                                                        }
                                                    }
                                                    None => {
                                                        continue;
                                                    }
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                    llvm_ir::Operand::LocalOperand { name, ty: _ } => {
                                        let name =
                                            name.to_string().chars().skip(1).collect::<String>();
                                        if !name.eq(&now) {
                                            continue;
                                        }
                                        let debug_location = inst.get_debug_loc();
                                        match debug_location {
                                            Some(debug_info) => {
                                                let file = debug_info.filename.clone();
                                                let line = debug_info.line;
                                                let column = debug_info.col;

                                                let debug_info = format!(
                                                    "Function: {:?} file: {:?} line: {:?} column: {:?}",
                                                    demangle_next_str, &file, &line, &column
                                                );

                                                let key = format!(
                                                    "Function:{} File:{} Line:{}, Column:{}",
                                                    next,
                                                    &file,
                                                    &line,
                                                    &column.unwrap_or(0).to_string()
                                                );

                                                if visit.get(&key).is_none() {
                                                    visit.insert(key.clone(), true);
                                                    let mut path_next = path.clone();
                                                    path_next.push(debug_info);
                                                    queue.push_back((next.to_string(), path_next));
                                                }
                                            }
                                            None => {
                                                continue;
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        interfaces.push(interface);
    }
    let mut file = std::fs::File::create("interface.json").unwrap();
    std::io::Write::write_all(
        &mut file,
        serde_json::to_string(&interfaces).unwrap().as_bytes(),
    )
    .unwrap();
    info!("End Src Level Analyzer");
}
