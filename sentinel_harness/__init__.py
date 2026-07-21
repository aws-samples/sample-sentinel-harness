"""sentinel-harness — production SecOps agents as configuration on Amazon Bedrock AgentCore Harness."""
from .core import (  # noqa: F401
    create_harness, update_harness, wait_ready, invoke, invoke_and_meter,
    invoke_with_tool_result, invoke_with_tool_results, new_session,
    create_harness_endpoint, get_harness_endpoint, update_harness_endpoint,
    promote_harness_endpoint, list_harness_endpoints, list_harness_versions,
    delete_harness_endpoint,
    bedrock_model, tool_code_interpreter, tool_remote_mcp, tool_gateway, tool_inline,
    managed_memory, byo_memory, delete_harness, cleanup, list_harnesses,
    MODEL_SONNET, MODEL_HAIKU, MODEL_OPUS, REGION,
)
from .loader import load_harness_config, create_from_config  # noqa: F401
from .exporter import export_harness_to_strands  # noqa: F401
from .gateway import (  # noqa: F401
    create_gateway, wait_gateway_ready, create_gateway_target,
    lambda_mcp_target, openapi_http_target, mcp_server_target,
    cognito_jwt_authorizer, lambda_interceptor, policy_engine_config,
    INTERCEPTION_POINTS, POLICY_ENGINE_MODES,
    delete_gateway, list_gateways, cleanup_gateways,
    list_gateway_targets, delete_gateway_target, update_gateway_target,
    synchronize_gateway_targets,
)
from .factory import (  # noqa: F401
    provision_fleet, teardown_fleet, FactoryError, ENV_TAG_KEY,
)
from .registry import (  # noqa: F401
    ToolRegistry, ToolEntry, GovernanceReport, RegistryError, load_registry,
)
from .registry_live import (  # noqa: F401
    create_registry, get_registry, delete_registry,
    create_skill_record, create_custom_record, list_records, submit_for_approval,
    RegistryLiveError, DESCRIPTOR_TYPES,
)
from .sandbox_hooks import (  # noqa: F401
    validate_command, validate_path, ALLOWED_COMMANDS, SANDBOX_ROOTS,
)
from .simulation import (  # noqa: F401
    PlayModeRunner, PlanState, StepState, DEFAULT_PLAN, PLAY_MODE_SYSTEM,
    exec_technique_gate, save_checkpoint, load_checkpoint,
    auto_approve, auto_reject, reject_after,
)
from .feedback import (  # noqa: F401
    FeedbackEvent, TenantFactStore, record_disposition, detect_triggers,
    managed_memory_writer, DISPOSITIONS, detect_score_decay,
)
from .observability import (  # noqa: F401
    token_metric_line, emit_token_metric, emit_token_metric_from_result, put_metric,
    metric_line, emit_metric, emit_invoke_latency, emit_tool_calls, emit_error,
    emit_hitl_gate, emit_eval_score, METRIC_NAMESPACE, TOKENS_METRIC_NAME, METRIC_FIELDS,
)
from .loop_safety import (  # noqa: F401
    regression_guard, apply_safety_veto, dimension_verdict,
    parse_dimension_scores, safety_failures, DEFAULT_THRESHOLD, SAFETY_DIMENSIONS,
)
from .provenance import (  # noqa: F401
    record_run, load_ledger, verify_ledger, compute_record_hash,
    LedgerEntry, ProvenanceError, DEFAULT_LEDGER_PATH,
)
from .logutil import get_logger, configure_logging, ROOT_LOGGER_NAME  # noqa: F401

# Version is single-sourced from the installed package metadata (pyproject.toml).
# The literal fallback keeps `__version__` correct for source checkouts that were
# never installed (e.g. editable-import from a bare clone); it MUST stay in sync
# with pyproject.toml's version. A test could assert the two match.
try:
    from importlib.metadata import PackageNotFoundError, version as _pkg_version

    __version__ = _pkg_version("sentinel-harness")
except PackageNotFoundError:  # not installed (bare source checkout)
    __version__ = "0.5.1"
