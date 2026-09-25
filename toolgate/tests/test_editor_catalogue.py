from toolgate.core import control_plane as cp
from toolgate.core import publications
from toolgate.tests.test_owner_channel import HEADERS, gate  # noqa: F401


def test_catalogue_search_and_pagination_never_expose_executor_or_credentials(gate):
    client = gate[0]
    for identity in ('aa', 'ab', 'bb'):
        cp.create_tool({'id': identity, 'name': f'Tool {identity}', 'description': 'Searchable',
            'inputs': [{'name': 'text', 'type': 'string', 'default': 'private-default'}],
            'execution': {'type': 'http_json', 'secret_headers': {'Authorization': 'PRIVATE_REF'},
                          'url': 'https://private.invalid'}, 'policy': {'private': 'hidden'}})
    cp.create_tool({'id': 'blocked', 'authorization': 'blocked'})
    path = '/v2/owner/editor-capabilities'
    assert client.get(path).status_code == 401
    first = client.get(path, headers=HEADERS, params={'limit': 1, 'q': 'Tool a'}).json()
    assert first['next_after'] == 'aa'
    assert first['items'][0]['id'] == 'aa'
    assert 'private' not in str(first).lower()
    second = client.get(path, headers=HEADERS, params={'limit': 1, 'q': 'Tool a', 'after': 'aa'}).json()
    assert [item['id'] for item in second['items']] == ['ab']
    assert second['next_after'] is None
    assert client.get(path, headers=HEADERS, params={'q': 'blocked'}).json()['items'] == []


def test_workflow_catalogue_offers_only_latest_available_publication(gate):
    client = gate[0]
    definition = cp.create_automation({'id': 'flow', 'name': 'Published flow', 'status': 'active',
                                       'workflow': [{'type': 'return', 'value': 1}]})
    path = '/v2/owner/editor-capabilities?kind=workflow'
    assert client.get(path, headers=HEADERS).json()['items'] == []
    publications.publish('automation', 'flow', 1)
    cp.update_automation('flow', {**definition, 'name': 'Unpublished edits'})
    first = client.get(path, headers=HEADERS).json()['items']
    assert len(first) == 1 and first[0]['name'] == 'Published flow' and first[0]['version'] == 1
    publications.publish('automation', 'flow', 2)
    assert client.get(path, headers=HEADERS).json()['items'][0]['version'] == 2
    cp.remove('automation', 'flow')
    assert client.get(path, headers=HEADERS).json()['items'] == []
