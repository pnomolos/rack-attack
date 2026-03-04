mod body;
mod engine;
mod field;
mod ip_matcher;
mod jwt;
mod query;
mod request_data;
mod result;
mod rule;

use engine::RuleSet;
use magnus::{function, method, prelude::*, Error, Ruby, Value};
use request_data::RequestData;
use result::EvaluationResult;
use std::ffi::c_void;

/// Wrapper around RuleSet to make it a Ruby object via magnus.
///
/// `RuleSet` is structurally `Send + Sync`: all fields (Vec<Rule>, compiled Regex,
/// HashSet, IpNet, JwtConfig with DecodingKey/Validation) are `Send + Sync`.
/// Per-request caches (JwtData, QueryData, BodyData) are stack-local in `evaluate()`.
#[magnus::wrap(class = "RackAttackNative::RuleSet")]
struct RubyRuleSet {
    inner: RuleSet,
}

/// Arguments passed through `rb_thread_call_without_gvl` for GVL-free evaluation.
struct EvalArgs<'a> {
    rule_set: &'a RuleSet,
    request: &'a RequestData,
    result: Option<EvaluationResult>,
}

/// Callback invoked without the GVL. Performs pure-Rust rule evaluation.
///
/// # Safety
/// - `arg` must point to a valid `EvalArgs` that outlives this call.
/// - No Ruby API calls are made inside this function.
/// - `catch_unwind` prevents panics from unwinding through C frames.
unsafe extern "C" fn eval_without_gvl(arg: *mut c_void) -> *mut c_void {
    let args = &mut *(arg as *mut EvalArgs);
    args.result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        args.rule_set.evaluate(args.request)
    }))
    .ok();
    std::ptr::null_mut()
}

impl RubyRuleSet {
    fn from_json(json: String) -> Result<Self, Error> {
        let rs = RuleSet::from_json(&json).map_err(|e| {
            let ruby = Ruby::get().unwrap();
            Error::new(ruby.exception_arg_error(), format!("Failed to compile rules: {}", e))
        })?;
        Ok(RubyRuleSet { inner: rs })
    }

    fn evaluate(&self, rb_hash: Value) -> Result<Value, Error> {
        let ruby = Ruby::get().unwrap();

        // Phase 1 (with GVL): deserialize Ruby Hash → RequestData
        let data: RequestData = serde_magnus::deserialize(&ruby, rb_hash).map_err(|e| {
            Error::new(
                ruby.exception_arg_error(),
                format!("Failed to deserialize request data: {}", e),
            )
        })?;

        // Phase 2 (without GVL): pure-Rust rule evaluation
        let mut args = EvalArgs {
            rule_set: &self.inner,
            request: &data,
            result: None,
        };

        unsafe {
            rb_sys::rb_thread_call_without_gvl(
                Some(eval_without_gvl),
                &mut args as *mut EvalArgs as *mut c_void,
                None, // no UBF — evaluation is pure CPU, typically <20µs
                std::ptr::null_mut(),
            );
        }

        let result = args.result.ok_or_else(|| {
            Error::new(
                ruby.exception_runtime_error(),
                "Rule evaluation panicked",
            )
        })?;

        // Phase 3 (with GVL): serialize EvaluationResult → Ruby Hash
        serde_magnus::serialize(&ruby, &result).map_err(|e| {
            Error::new(
                ruby.exception_runtime_error(),
                format!("Failed to serialize result: {}", e),
            )
        })
    }

    fn rule_count(&self) -> usize {
        let rs = &self.inner;
        rs.safelists.len() + rs.blocklists.len() + rs.throttles.len() + rs.tracks.len()
    }
}

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let module = ruby.define_module("RackAttackNative")?;
    let class = module.define_class("RuleSet", ruby.class_object())?;

    class.define_singleton_method("from_json", function!(RubyRuleSet::from_json, 1))?;
    class.define_method("evaluate", method!(RubyRuleSet::evaluate, 1))?;
    class.define_method("rule_count", method!(RubyRuleSet::rule_count, 0))?;

    Ok(())
}
