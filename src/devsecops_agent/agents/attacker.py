import logging
from typing import Optional
from devsecops_agent.agents.base import BaseAgent
from devsecops_agent.sandbox.base import BaseSandbox
from devsecops_agent.schemas.vulnerability import VulnerabilityCandidate
from devsecops_agent.schemas.exploit import (
    ExploitScript,
    ExploitReport,
    EvidenceType,
    ExecutionResult
)
from devsecops_agent.llm.base import BaseLLMClient

logger = logging.getLogger(__name__)


class AttackerAgent(BaseAgent):
    """
    Red Team Agent: Synthesizes dynamic exploit scripts and executes them inside
    the isolated sandbox to confirm or refute vulnerability warnings (Algorithm 2).
    """

    SYSTEM_PROMPT = (
        "You are an expert Red Team Security Engineer assisting an autonomous DevSecOps verification pipeline. "
        "Your mission is to dynamically prove whether a suspected vulnerability in a code change is exploitable in runtime. "
        "Generate a self-contained Python validation test script ('exploit_test.py') that interacts with the target code or service. "
        "CRITICAL EXECUTION CONVENTIONS:\n"
        "1. If the vulnerability is successfully triggered (e.g., SQL leak, unauthorized file read, command execution, or crash), "
        "   the script MUST print 'CONFIRMED_EXPLOIT: <details>' and exit with non-zero exit code (sys.exit(1)).\n"
        "2. If the application handles the input securely or the flaw cannot be reproduced, exit cleanly with sys.exit(0).\n"
        "3. Keep the script concise, self-contained, and run with a reasonable timeout."
    )

    def __init__(self, llm_client: BaseLLMClient):
        super().__init__(name="AttackerAgent", role="Red Team Exploit Verification", llm_client=llm_client)

    def generate_exploit_script(self, candidate: VulnerabilityCandidate) -> ExploitScript:
        """Prompts LLM to synthesize an exploit test script for the candidate."""
        context = candidate.context
        func_src = context.enclosing_function_source if context else "N/A"
        imports_str = "\n".join(context.imports) if context and context.imports else ""
        diff_hunk = context.diff_hunk if context else ""

        prompt = (
            f"Vulnerability Candidate ID: {candidate.id}\n"
            f"Title: {candidate.title}\n"
            f"Suspected Classification: {candidate.owasp_category.value} ({candidate.cwe_id})\n"
            f"Target File: {candidate.target_file}\n"
            f"Modified Lines: {candidate.line_numbers}\n\n"
            f"Diff Context:\n```\n{diff_hunk}\n```\n\n"
            f"Enclosing Function ({context.enclosing_function_name if context else 'root'}):\n```python\n{func_src}\n```\n\n"
            f"Imports:\n```python\n{imports_str}\n```\n\n"
            "Synthesize an automated Python exploit test script to confirm this vulnerability."
        )

        return self.llm.generate_json(
            prompt=prompt,
            schema_cls=ExploitScript,
            system_prompt=self.SYSTEM_PROMPT,
            temperature=0.1
        )

    def execute_and_verify(
        self, candidate: VulnerabilityCandidate, sandbox: BaseSandbox
    ) -> ExploitReport:
        """
        Runs Algorithm 2:
        1. Synthesizes exploit script.
        2. Writes script into sandbox.
        3. Executes script in sandbox.
        4. Analyzes stdout/stderr/exit_code to confirm or refute exploitability.
        """
        logger.info(f"[AttackerAgent] Generating exploit verification script for {candidate.id}...")
        script = self.generate_exploit_script(candidate)

        # Write script to sandbox
        sandbox.write_file(script.file_name, script.code)

        # Execute script in sandbox
        logger.info(f"[AttackerAgent] Executing exploit script: {script.entrypoint_command}")
        exec_res: ExecutionResult = sandbox.execute(
            script.entrypoint_command, timeout=script.timeout_seconds
        )

        # Check for confirmed exploit condition
        is_confirmed = False
        evidence_type = EvidenceType.NONE
        output_combined = f"{exec_res.stdout}\n{exec_res.stderr}"

        if exec_res.exit_code == 1 or "CONFIRMED_EXPLOIT" in output_combined:
            is_confirmed = True
            evidence_type = self._classify_evidence(output_combined, candidate)
        elif exec_res.exit_code != 0 and not exec_res.timed_out:
            # Check for crash tracebacks
            if "Traceback (most recent call last)" in output_combined or "Error:" in output_combined:
                is_confirmed = True
                evidence_type = EvidenceType.CRASH

        report = ExploitReport(
            candidate_id=candidate.id,
            confirmed=is_confirmed,
            evidence_type=evidence_type,
            script=script,
            execution_result=exec_res,
            reasoning=f"Attacker script exited with code {exec_res.exit_code}. Confirmed={is_confirmed}.",
            raw_evidence=output_combined.strip()
        )

        logger.info(
            f"[AttackerAgent] Candidate {candidate.id} result: "
            f"Confirmed={is_confirmed}, EvidenceType={evidence_type.value}"
        )
        return report

    def _classify_evidence(self, output: str, candidate: VulnerabilityCandidate) -> EvidenceType:
        lower = output.lower()
        if "sql" in lower or "leak" in lower or "dump" in lower:
            return EvidenceType.DATA_LEAK
        if "command" in lower or "pwned" in lower or "uid=" in lower:
            return EvidenceType.COMMAND_EXECUTION
        if "traceback" in lower or "internal server error" in lower:
            return EvidenceType.CRASH
        if "admin" in lower or "unauthorized" in lower:
            return EvidenceType.UNAUTHORIZED_ACCESS
        return EvidenceType.CRASH
