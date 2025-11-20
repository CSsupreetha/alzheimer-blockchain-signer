# signer.py
import os
import json
import hmac
import hashlib
import logging
from flask import Flask, request, jsonify
from web3 import Web3

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("signer")

# --- configuration via env ---
INFURA_URL = os.getenv("INFURA_URL")
PRIVATE_KEY = os.getenv("SIGNER_PRIVATE_KEY")  # full hex private key (0x...)
HMAC_SECRET = os.getenv("SIGNER_HMAC_SECRET")  # long random string
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")  # 0x...
CONTRACT_ABI_FILE = os.getenv("CONTRACT_ABI_FILE", "contract_abi.json")  # file packaged in repo

# Basic checks
if not INFURA_URL:
    log.error("INFURA_URL not set")
    raise SystemExit(1)
if not PRIVATE_KEY:
    log.error("SIGNER_PRIVATE_KEY not set")
    raise SystemExit(1)
if not HMAC_SECRET:
    log.error("SIGNER_HMAC_SECRET not set")
    raise SystemExit(1)
if not CONTRACT_ADDRESS:
    log.error("CONTRACT_ADDRESS not set")
    raise SystemExit(1)

# web3 init
w3 = Web3(Web3.HTTPProvider(INFURA_URL))
if not w3.is_connected():
    log.error("Cannot connect to Ethereum provider at INFURA_URL")
    raise SystemExit(1)

acct = w3.eth.account.from_key(PRIVATE_KEY)
log.info("Signer ready, address: %s", acct.address)

# load contract ABI from file packaged in repo
try:
    with open(CONTRACT_ABI_FILE, "r", encoding="utf-8") as f:
        contract_abi = json.load(f)
except Exception as e:
    log.exception("Failed to load contract ABI file: %s", e)
    raise SystemExit(1)

contract = w3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=contract_abi)

app = Flask(__name__)

def verify_hmac(body_bytes: bytes, header_sig: str) -> bool:
    if not header_sig:
        return False
    if header_sig.startswith("sha256="):
        header_sig = header_sig.split("=", 1)[1]
    mac = hmac.new(HMAC_SECRET.encode(), body_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, header_sig)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "address": acct.address})

@app.route("/sign_and_send", methods=["POST"])
def sign_and_send():
    """
    Expected JSON:
    {
      "image_hash": "<hex string or base64 id>",
      "metadata_hash": "<hex string>",
      "predicted_stage": <int>,
      "confidence": <int>   # percent 0..100 or integer
    }
    Headers:
      X-Hmac-Signature: sha256=<hex>
    """
    try:
        raw = request.get_data()
        sig = request.headers.get("X-Hmac-Signature")
        if not verify_hmac(raw, sig):
            return jsonify({"error": "unauthorized"}), 401

        req = request.get_json(force=True)
        image_hash = req.get("image_hash")
        metadata_hash = req.get("metadata_hash")
        stage = int(req.get("predicted_stage") or 0)
        confidence = int(req.get("confidence") or 0)

        # build contract function object
        func = contract.functions.storePrediction(image_hash, metadata_hash, int(stage), int(confidence))

        # nonce & gas
        tx_from = acct.address
        nonce = w3.eth.get_transaction_count(tx_from)
        try:
            gas_est = func.estimateGas({"from": tx_from})
        except Exception:
            gas_est = 250_000

        try:
            gas_price = w3.eth.generate_gas_price()
            if gas_price is None:
                gas_price = w3.eth.gas_price
        except Exception:
            gas_price = w3.toWei("20", "gwei")

        tx_dict = func.buildTransaction({
            "from": tx_from,
            "nonce": nonce,
            "gas": int(gas_est * 1.1),
            "gasPrice": int(gas_price),
            "chainId": w3.eth.chain_id
        })

        signed = w3.eth.account.sign_transaction(tx_dict, PRIVATE_KEY)
        raw_tx = signed.rawTransaction
        tx_hash = w3.eth.send_raw_transaction(raw_tx)
        tx_hex = w3.to_hex(tx_hash)

        log.info("Broadcasted tx: %s", tx_hex)

        return jsonify({"tx_hash": tx_hex, "metadata_hash": metadata_hash}), 200

    except Exception as e:
        log.exception("sign_and_send failed: %s", e)
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
