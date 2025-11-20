import os
import json
import hmac
import hashlib
import logging
from flask import Flask, request, jsonify
from web3 import Web3

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("signer")

# -------------------------------
# ENV VARIABLES (Railway)
# -------------------------------
INFURA_URL = os.getenv("RPC_URL") or os.getenv("INFURA_URL")
PRIVATE_KEY = os.getenv("SIGNER_PRIVATE_KEY")
HMAC_SECRET = os.getenv("SIGNER_HMAC_SECRET")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
CONTRACT_ABI_FILE = os.getenv("CONTRACT_ABI_FILE", "contract_abi.json")

if not INFURA_URL:
    raise RuntimeError("Missing RPC_URL / INFURA_URL")
if not PRIVATE_KEY:
    raise RuntimeError("Missing SIGNER_PRIVATE_KEY")
if not HMAC_SECRET:
    raise RuntimeError("Missing SIGNER_HMAC_SECRET")
if not CONTRACT_ADDRESS:
    raise RuntimeError("Missing CONTRACT_ADDRESS")

# -------------------------------
# FLASK APP
# -------------------------------
app = Flask(__name__)

# -------------------------------
# LAZY WEB3 INIT (Prevents startup crash)
# -------------------------------
w3 = None
acct = None
contract = None

def init_web3():
    global w3, acct, contract

    if w3 is not None:
        return  # already initialized

    log.info("Initializing Web3...")

    w3 = Web3(Web3.HTTPProvider(INFURA_URL))

    if not w3.is_connected():
        raise RuntimeError("Failed to connect to RPC provider.")

    acct = w3.eth.account.from_key(PRIVATE_KEY)
    log.info("Signer loaded. Address: %s", acct.address)

    # Load ABI
    try:
        with open(CONTRACT_ABI_FILE, "r", encoding="utf-8") as f:
            abi = json.load(f)
    except Exception as e:
        log.error("Cannot read ABI file: %s", e)
        raise

    contract = w3.eth.contract(
        address=Web3.to_checksum_address(CONTRACT_ADDRESS),
        abi=abi
    )

    log.info("Contract loaded @ %s", CONTRACT_ADDRESS)


# -------------------------------
# HEALTH ENDPOINT (must always work)
# -------------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


# -------------------------------
# HMAC VERIFICATION
# -------------------------------
def verify_hmac(body_bytes: bytes, header_sig: str) -> bool:
    if not header_sig:
        return False
    if header_sig.startswith("sha256="):
        header_sig = header_sig.split("=", 1)[1]

    mac = hmac.new(
        HMAC_SECRET.encode(),
        body_bytes,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(mac, header_sig)


# -------------------------------
# SIGN-AND-SEND TX ENDPOINT
# -------------------------------
@app.route("/sign_and_send", methods=["POST"])
def sign_and_send():
    try:
        init_web3()

        # Validate HMAC
        raw = request.get_data()
        sig = request.headers.get("X-Hmac-Signature")

        if not verify_hmac(raw, sig):
            return jsonify({"error": "unauthorized"}), 401

        data = request.get_json(force=True)

        image_hash = data.get("image_hash")
        metadata_hash = data.get("metadata_hash")
        stage = int(data.get("predicted_stage", 0))
        confidence = int(data.get("confidence", 0))

        log.info("Incoming request: %s", data)

        func = contract.functions.storePrediction(
            image_hash,
            metadata_hash,
            stage,
            confidence
        )

        tx_from = acct.address
        nonce = w3.eth.get_transaction_count(tx_from)

        try:
            gas_est = func.estimateGas({"from": tx_from})
        except Exception:
            gas_est = 250000

        gas_price = w3.eth.gas_price

        tx_dict = func.build_transaction({
            "from": tx_from,
            "nonce": nonce,
            "gas": int(gas_est * 1.1),
            "gasPrice": int(gas_price),
            "chainId": w3.eth.chain_id
        })

        signed = w3.eth.account.sign_transaction(tx_dict, PRIVATE_KEY)
        tx_hash = w3.eth.send_raw_transaction(signed.rawTransaction)
        tx_hex = w3.to_hex(tx_hash)

        log.info("TX broadcasted: %s", tx_hex)

        return jsonify({"tx_hash": tx_hex}), 200

    except Exception as e:
        log.exception("Signing failed: %s", e)
        return jsonify({"error": str(e)}), 500


# -------------------------------
# LOCAL DEV ENTRYPOINT
# -------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
