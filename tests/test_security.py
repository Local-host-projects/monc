from app.security import decrypt_policy, encrypt_policy


def test_policy_encryption_round_trip():
    policy = {"source_rules": ["Maximum NGN 10,000 per transaction"], "compiled": [], "unsupported": []}
    ciphertext, nonce = encrypt_policy(policy)
    assert "Maximum" not in ciphertext
    assert decrypt_policy(ciphertext, nonce) == policy
