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


def slack_get_channel_info(
    auth: Annotated[TokenAuth, 'Authentication instance'],
    channel_id: Annotated[str, 'The ID of the channel to fetch information for.'],
) -> dict[str, Any]:
    client = _get_client(auth.token)
    response = client.conversations_info(channel=channel_id)
    return response['channel']


def slack_get_channel_history(
    auth: Annotated[TokenAuth, 'Authentication instance'],
    channel_id: Annotated[str, 'The ID of the channel to fetch history for'],
    limit: Annotated[int, 'The max number of messages to show'],
) -> list[dict[str, Any]]:
    client = _get_client(auth.token)
    response = client.conversations_history(channel=channel_id, limit=limit)
    return response['messages']


def write_to_json_file(channel: dict[str, Any], messages: list[dict[str, Any]], filename: str) -> None:
    structured_data = {
        "channels": [
            {
                "id": channel.get("id"),
                "name": channel.get("name"),
                "messages": [
                    {
                        "user": msg.get("user"),
                        "text": msg.get("text"),
                        "timestamp": msg.get("ts")
                    }
                    for msg in messages
                    if "text" in msg and "ts" in msg
                ]
            }
        ]
    }
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(structured_data, f, ensure_ascii=False, indent=2)


# ==== MAIN EXECUTION ====

SLACK_TOKEN = os.environ.get("SLACK_TOKEN")
CHANNEL_ID = os.environ.get("CHANNEL_ID")

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
messages = slack_get_channel_history(auth, CHANNEL_ID, 10)

write_to_json_file(channel_info, messages, "slack.json")
print("Data written to slack.json")
