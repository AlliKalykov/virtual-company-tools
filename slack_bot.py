import os
import json
import logging
from datetime import datetime, timedelta
from typing import Annotated, Any
from dotenv import load_dotenv

from slack_sdk import WebClient
from slack_sdk.http_retry.builtin_handlers import ConnectionErrorRetryHandler, RateLimitErrorRetryHandler

from auth import Token, TokenAuth

load_dotenv()
logger = logging.getLogger(__name__)


def _get_client(token: str) -> WebClient:
    try:
        return WebClient(
            token=token,
            retry_handlers=[
                RateLimitErrorRetryHandler(max_retry_count=10),
                ConnectionErrorRetryHandler(),
            ],
        )
    except Exception as e:
        logger.error(f'Error getting client: {e}')
        raise RuntimeError(f'Error getting client: {e.__class__.__name__} {e}')


def slack_get_channel_info(auth: TokenAuth, channel_id: str) -> dict[str, Any]:
    client = _get_client(auth.token)
    return client.conversations_info(channel=channel_id)['channel']


def slack_get_channel_history(auth: TokenAuth, channel_id: str, limit: int) -> list[dict[str, Any]]:
    client = _get_client(auth.token)
    return client.conversations_history(channel=channel_id, limit=limit)['messages']


def slack_get_channel_members(auth: TokenAuth, channel_id: str) -> list[str]:
    client = _get_client(auth.token)
    return client.conversations_members(channel=channel_id)['members']


def slack_get_users(auth: TokenAuth) -> list[dict[str, Any]]:
    client = _get_client(auth.token)
    users = []
    cursor = None
    while True:
        response = client.users_list(cursor=cursor, limit=10)
        users.extend(response['members'])
        cursor = response.get('response_metadata', {}).get('next_cursor')
        if not cursor:
            break
    return users


def write_to_json_file(
    channel: dict[str, Any],
    members: list[str],
    users: list[dict[str, Any]],
    messages: list[dict[str, Any]],
    filename: str
) -> None:
    channel_id = channel.get("id")
    structured = {
        "messages": [
            {
                "id": f"msg_{str(i + 1).zfill(3)}",
                "channel_id": channel_id,
                "user_id": msg.get("user"),
                "text": msg.get("text", ""),
                "ts": msg["ts"]
            }
            for i, msg in enumerate(messages)
            if "user" in msg and "text" in msg and "ts" in msg
        ],
        "channels": [
            {
                "id": channel_id,
                "name": channel.get("name"),
                "is_private": channel.get("is_private", False),
                "members": members
            }
        ],
        "users": [
            {
                "id": user["id"],
                "name": user["name"],
                "real_name": user.get("real_name", ""),
                "email": user.get("profile", {}).get("email", "")
            }
            for user in users
            if user["id"] in members
        ]
    }

    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(structured, f, ensure_ascii=False, indent=2)


# ==== MAIN EXECUTION ====

SLACK_TOKEN = os.environ.get("SLACK_TOKEN")
CHANNEL_ID = os.environ.get("SLACK_CHANNEL_ID")

if not SLACK_TOKEN or not CHANNEL_ID:
    raise EnvironmentError("SLACK_TOKEN and CHANNEL_ID must be set in environment variables")

token = Token(
    token=SLACK_TOKEN,
    expires_at=datetime.now() + timedelta(weeks=30),
    meta={},
)

auth = TokenAuth(
    service='slack',
    token=token.token,
)

channel_info = slack_get_channel_info(auth, CHANNEL_ID)
messages = slack_get_channel_history(auth, CHANNEL_ID, 100)
members = slack_get_channel_members(auth, CHANNEL_ID)
users = slack_get_users(auth)

write_to_json_file(channel_info, members, users, messages, "slack.json")
print("Data written to slack.json")
