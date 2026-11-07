#!/usr/bin/env python3
"""Read-only trial commit decision, never performs or authorizes host network mutations."""
import importlib.util
from pathlib import Path

ROOT=Path(__file__).resolve().parent
def load(filename):
    spec=importlib.util.spec_from_file_location(filename.replace('-','_'),ROOT/filename)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
proof_validator=load('vpngw-vpn-cutover-evidence.py')
contract=load('vpngw-vpn-cutover-execution-contract.py')

def assess(*,policy,vpn_interface,expected_public_ip,proof,transaction):
    inspected=proof_validator.verify(proof,policy=policy,
                                     vpn_interface=vpn_interface,
                                     expected_public_ip=expected_public_ip)
    state=contract.validate_evidence(transaction)
    blockers=list(inspected['errors'])
    blockers.extend('transaction_'+item for item in state['missing'])
    # Even valid synthetic proof must not enable production cutover;
    # authenticated per-device collection is not available yet.
    blockers.append('authenticated_client_collector_unavailable')
    return {'policy':policy,'client_proof_valid':inspected['verified'],
            'transaction_checks_complete':not state['missing'],
            'can_commit':False,'cutover_enabled':False,
            'blockers':blockers,'network_changes':False}
