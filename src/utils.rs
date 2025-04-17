use llvm_ir::BasicBlock;
use log::info;
use rustc_demangle::demangle;
use std::{
    collections::BTreeSet,
    hash::{DefaultHasher, Hash, Hasher},
};

pub fn demangle_name(name: &String) -> String {
    format!("{:#}", demangle(name))
}

pub fn get_hash(name: impl Hash) -> String {
    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    let hash = hasher.finish();
    format!("{:x}", hash)
}

pub fn bb_contains(bb: &BasicBlock, ffis: &BTreeSet<String>) -> bool {
    let mut contain_ffi = false;
    for inst in &bb.instrs {
        match inst {
            llvm_ir::Instruction::Call(call) => {
                let call_function = &call.function;
                if call_function.is_right() {
                    let call_function = call_function.clone().right().unwrap();
                    match call_function {
                        llvm_ir::Operand::ConstantOperand(const_ref) => match const_ref.as_ref() {
                            llvm_ir::Constant::GlobalReference { name, ty: _ } => {
                                let call_function_name =
                                    &name.to_string().chars().skip(1).collect::<String>();
                                for ffi in ffis {
                                    if call_function_name.eq(ffi) {
                                        info!("call_function: {:?} ffi: {:?}", call_function_name, ffi);
                                        contain_ffi = true;
                                        break;
                                    }
                                }
                                if contain_ffi {
                                    break;
                                }
                            }
                            _ => {}
                        },
                        llvm_ir::Operand::LocalOperand { name, ty: _ } => {
                            let call_function_name =
                                &name.to_string().chars().skip(1).collect::<String>();
                            for ffi in ffis {
                                if call_function_name.contains(ffi) {
                                    // info!("call_function: {:?} ffi: {:?}", call_function_name, ffi);
                                    contain_ffi = true;
                                    break;
                                }
                            }
                            if contain_ffi {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    contain_ffi
}
