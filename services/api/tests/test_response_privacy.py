"""Sensitive API and authorization results must be private and uncacheable."""


def test_success_and_denied_responses_are_not_cacheable(harness):
    client, auth, _, _ = harness
    cases = [
        client.get("/healthz"),
        client.get("/v1/overview", headers=auth()),
        client.get("/v1/overview"),
        client.get("/v1/assets", headers=auth("owner-A", "00000000-0000-0000-0000-000000000000")),
    ]
    assert [item.status_code for item in cases] == [200, 200, 401, 403]
    for response in cases:
        assert "no-store" in response.headers["cache-control"]
        assert "private" in response.headers["cache-control"]
        assert response.headers["pragma"] == "no-cache"
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["referrer-policy"] == "no-referrer"
