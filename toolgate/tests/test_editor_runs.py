import uuid

from toolgate.core import control_plane as cp, owner_channel, execution_journal as journal
from toolgate.tests.test_owner_channel import gate, HEADERS  # noqa: F401
from toolgate.tests.test_editor_owner_publication import save, publish


def setup(gate, authorization='auto'):
    client, agent, key = gate
    assert save(client).status_code == 200
    published = publish(client, authorization=authorization).json()
    headers = {**HEADERS, 'X-ToolGate-Execution-Key': key}
    target = {'version': published['version'], 'digest': published['digest']}
    return client, agent, headers, target


def test_access_requires_both_channels_and_changes_only_reviewed_workflow(gate):
    client, agent, headers, target = setup(gate)
    path = '/v2/owner/editor-drafts/example/access'
    for credentials in (HEADERS, {'X-ToolGate-Execution-Key': gate[2]}, {}):
        assert client.post(path, headers=credentials, json={**target, 'enabled': True}).status_code == 401
    result = client.post(path, headers=headers, json={**target, 'enabled': True})
    assert result.status_code == 200, result.text
    assert result.json()['enabled'] is True
    assert 'tool:example' in cp.authenticate_agent(gate[2])['scopes']
    assert client.post(path, headers=headers, json={**target, 'enabled': False}).json()['enabled'] is False
    assert cp.authenticate_agent(gate[2])['scopes'] == ['tool:example']


def test_real_run_replay_conflict_and_persisted_history(gate):
    client, agent, headers, target = setup(gate)
    base = '/v2/owner/editor-drafts/example'
    client.post(base + '/access', headers=headers, json={**target, 'enabled': True}).raise_for_status()
    body = {**target, 'action_id': 'editor_' + uuid.uuid4().hex, 'args': {}}
    first = client.post(base + '/runs', headers=headers, json=body)
    assert first.status_code == 200, first.text
    assert first.json()['code'] == 'OK' and first.json()['result']['result'] == 7
    assert client.post(base + '/runs', headers=headers, json=body).json() == first.json()
    assert len(journal.list_actions()) == 1
    assert client.post(base + '/runs', headers=headers, json={**body, 'args': {'changed': True}}).status_code == 409
    history = client.get(base + '/runs', headers=headers).json()['items']
    assert history[0]['response'] == first.json()
    assert history[0]['action_id'] == body['action_id']


def test_approval_resumes_same_action_and_never_duplicates_dispatch(gate):
    client, agent, headers, target = setup(gate, 'owner_confirmation')
    base = '/v2/owner/editor-drafts/example'
    client.post(base + '/access', headers=headers, json={**target, 'enabled': True}).raise_for_status()
    body = {**target, 'action_id': 'editor_' + uuid.uuid4().hex, 'args': {}}
    waiting = client.post(base + '/runs', headers=headers, json=body).json()
    assert waiting['code'] == 'CONFIRMATION_REQUIRED'
    assert client.post(base + '/runs', headers=headers, json=body).json() == waiting
    assert len(cp.list_objects('request')) == 1
    assert journal.list_actions() == []
    early = client.post(base + '/runs', headers=headers, json={**body, 'approval_request_id': waiting['request_id']}).json()
    assert early['code'] == 'CONFIRMATION_REQUIRED'
    owner_channel.decide(waiting['request_id'], 'approved', 'Owner reviewed this exact workflow.')
    result = client.post(base + '/runs', headers=headers, json={**body, 'approval_request_id': waiting['request_id']}).json()
    assert result['code'] == 'OK', result
    assert client.post(base + '/runs', headers=headers, json=body).json() == result
    assert len(journal.list_actions()) == 1


def test_no_scope_does_not_dispatch_and_wildcard_cannot_fake_revocation(gate):
    client, agent, headers, target = setup(gate)
    base = '/v2/owner/editor-drafts/example'
    body = {**target, 'action_id': 'editor_' + uuid.uuid4().hex, 'args': {}}
    assert client.post(base + '/runs', headers=headers, json=body).json()['code'] == 'POLICY_DENIED'
    assert journal.list_actions() == []
    cp.update_agent_key_scopes(agent['id'], ['automation:*'])
    assert client.post(base + '/access', headers=headers, json={**target, 'enabled': False}).status_code == 409


def test_lost_response_holds_request_without_second_dispatch(gate, monkeypatch):
    from toolgate.api import server
    client, agent, headers, target = setup(gate)
    base = '/v2/owner/editor-drafts/example'
    client.post(base + '/access', headers=headers, json={**target, 'enabled': True}).raise_for_status()
    body = {**target, 'action_id': 'editor_' + uuid.uuid4().hex, 'args': {}}
    calls = []
    def lost(*args, **kwargs):
        calls.append(1)
        raise RuntimeError('transport lost')
    monkeypatch.setattr(server, 'run_automation', lost)
    try:
        client.post(base + '/runs', headers=headers, json=body)
    except RuntimeError:
        pass
    assert client.post(base + '/runs', headers=headers, json=body).json()['code'] == 'OUTCOME_UNKNOWN'
    assert calls == [1]


def test_graph_input_defaults_work_without_changing_reviewed_arguments(gate):
    from toolgate.tests.test_editor_execution import linear
    client, _, key = gate
    document = linear(('result', 'return', {'value': '$input.count'}))
    document['inputs'] = [{'name': 'count', 'type': 'number', 'required': True, 'default': 4}]
    assert save(client, document).status_code == 200
    published = publish(client, authorization='auto').json()
    headers = {**HEADERS, 'X-ToolGate-Execution-Key': key}
    target = {'version': 1, 'digest': published['digest']}
    base = '/v2/owner/editor-drafts/example'
    client.post(base + '/access', headers=headers, json={**target, 'enabled': True}).raise_for_status()
    result = client.post(base + '/runs', headers=headers, json={**target, 'action_id': 'editor_' + uuid.uuid4().hex, 'args': {}}).json()
    assert result['code'] == 'OK' and result['result']['result'] == 4
    assert journal.get(result['action_id'])['args'] == {}


def test_agent_discovers_only_scoped_immutable_workflow_metadata(gate):
    client, _, headers, target = setup(gate)
    execution = {'X-ToolGate-Execution-Key': gate[2]}
    path = '/v2/agent/published-workflows'
    assert client.get(path, headers=execution).json() == []
    client.post('/v2/owner/editor-drafts/example/access', headers=headers,
                json={**target, 'enabled': True}).raise_for_status()
    rows = client.get(path, headers=execution).json()
    assert len(rows) == 1
    assert rows[0]['id'].endswith(':1:' + target['digest'])
    assert set(rows[0]) == {'id', 'name', 'description', 'inputs'}
    client.post('/v2/owner/editor-drafts/example/access', headers=headers,
                json={**target, 'enabled': False}).raise_for_status()
    assert client.get(path, headers=execution).json() == []


def test_hidden_editor_workflow_stays_out_of_agent_catalogue(gate):
    from toolgate.tests.test_editor_execution import linear
    client, _, key = gate
    document = linear(('result', 'return', {'value': 7}))
    document['agentVisible'] = False
    assert save(client, document).status_code == 200
    published = publish(client, authorization='auto').json()
    headers = {**HEADERS, 'X-ToolGate-Execution-Key': key}
    target = {'version': 1, 'digest': published['digest']}
    client.post('/v2/owner/editor-drafts/example/access', headers=headers,
                json={**target, 'enabled': True}).raise_for_status()
    assert client.get('/v2/agent/published-workflows', headers=headers).json() == []
