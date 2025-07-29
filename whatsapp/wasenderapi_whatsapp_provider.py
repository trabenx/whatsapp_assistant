import os
import json
import logging
from typing import Optional, Tuple

import config
from whatsapp.whatsapp_provider import WhatsAppProvider

from bot_handler import handle_incoming_message, find_media_info, handle_media_decryption

from wasenderapi import create_sync_wasender
from wasenderapi.webhook import WasenderWebhookEventType, BaseWebhookEvent, MessagesUpsertData, MessageKey
from wasenderapi.models import RetryConfig
from wasenderapi.errors import WasenderAPIError

class WASenderApiWhatsAppProvider(WhatsAppProvider):
    def __init__(self):
        super().__init__()
        self.client = create_sync_wasender(
            api_key=config.WASENDER_API_TOKEN,
            retry_options=RetryConfig(enabled=False),
            webhook_secret=config.WASENDER_WEBHOOK_SECRET,
            personal_access_token=config.WASENDER_PERSONAL_TOKEN
        )
    def send_message(self, to: str, message: str) -> dict:
        return {"status": "sent", "to": to, "message": message}

    def get_messages(self) -> list[dict]:
        return [{"from": "+123456", "body": "Hi!"}]

    def preprocess_incoming_message(self, message_content, media_result, message_id):
        updates_dict = {}
        if message_content:
            logging.info(f"Text: {message_content}")
            
        if media_result:
            media_info, media_type = media_result
            logging.info(f"Media found. Type: {media_type}. Attempting to decrypt...")

            decrypted_data = handle_media_decryption(media_info, media_type)
            logging.info(f"Successfully decrypted media. saving to file")
            extension = media_info.get('mimetype', 'application/octet-stream').split('/')[-1]
            filename = media_info.get('fileName') or f"{message_id}.{extension}"
            output_path = os.path.join(config.DOWNLOAD_DIR, os.path.basename(filename)) # Use basename to prevent path traversal
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            logging.info(f"Decrypted file saved to {output_path}")
            logging.info(f"Decrypted file available via {config.PUBLIC_URL}/download/{filename}")
            updates_dict[f"data/messages/message/{media_type}Message/url"] = f'{config.PUBLIC_URL}/download/{filename}'
        return updates_dict
    
    def update_dict_path(self, data, path, value, sep="/"):
        keys = path.split(sep)
        d = data
        for key in keys[:-1]:
            d = d.setdefault(key, {})  # Create nested dicts if not present
        d[keys[-1]] = value

    def parse_raw_message(self, raw_msg: dict) -> dict or None:
        """
        Parses the raw message object from the WasenderAPI webhook
        and transforms it into a standardized format for our bot.
        """
        if not isinstance(raw_msg, dict):
            return None

        key = raw_msg.get("key", {})
        message_content = raw_msg.get("message", {})
        
        if not key or not message_content:
            return None

        # This is our new, clean, and standardized message format
        parsed_message = {
            "id": key.get("id"),
            "from": key.get("remoteJid"),
            "from_me": key.get("fromMe", False),
            "type": None,
            "content": {}
        }

        # Determine message type and content
        if "conversation" in message_content and message_content["conversation"]:
            parsed_message["type"] = "text"
            parsed_message["content"]["body"] = message_content["conversation"]
        # Add other types as you discover their payload structure
        # For example, for an image:
        # elif "imageMessage" in message_content:
        #     parsed_message["type"] = "image"
        #     parsed_message["content"]["url"] = message_content["imageMessage"].get("url")
        #     parsed_message["content"]["caption"] = message_content["imageMessage"].get("caption")
        elif "videoMessage" in message_content and message_content["videoMessage"]:
            parsed_message["type"] = "video"
            parsed_message["content"]["body"] = message_content["videoMessage"]
        elif "imageMessage" in message_content and message_content["imageMessage"]:
            parsed_message["type"] = "image"
            parsed_message["content"]["body"] = message_content["imageMessage"]
        elif "audioMessage" in message_content and message_content["audioMessage"]:
            parsed_message["type"] = "audio"
            parsed_message["content"]["body"] = message_content["audioMessage"]
        else:
            # Unsupported message type for now
            return None

        return parsed_message

    def parse_remote_jid(self, remote_jid):
        try:
            user_part, domain = remote_jid.split("@")

            if domain == "s.whatsapp.net":
                return {
                    "chat_type": "private",
                    "phone_number": user_part
                }

            elif domain == "g.us":
                phone_number, group_id = user_part.split("-")
                return {
                    "chat_type": "group",
                    "phone_number": phone_number,
                    "group_id": group_id
                }

            else:
                return {
                    "chat_type": "unknown",
                    "raw": remote_jid
                }

        except ValueError:
            return {
                "error": "Invalid format",
                "raw": remote_jid
            }

    def webhook_handler(self, payload) -> Tuple[str, Optional[str]]:
        request_body = json.loads(payload.decode('utf-8'))
        event = BaseWebhookEvent.model_validate(request_body)
        match event.event:
            case WasenderWebhookEventType.MESSAGES_UPSERT:
                if not event.data:
                    logging.warning(f'[{event.event}] Ignoring message with no data.')
                    return ('skipped', "empty_data")
                if event.data.get('messages') is None:
                    logging.warning(f'[{event.event}] Ignoring message with no messages.')
                    return ('skipped', "empty_messages")
                
                if not isinstance(event.data['messages'].get('messageTimestamp'), int):
                    # Fix for an issue when sometimes we get dict instead of int
                    logging.warning(f"[{event.event}] Invalid timestamp, setting to None [{event.data['messages'].get('messageTimestamp')}].")
                    event.data['messages']['messageTimestamp'] = None
                message_upsert = MessagesUpsertData.model_validate(event.data['messages'])
                
                if not message_upsert.key:
                    logging.warning(f'[{event.event}] Ignoring message with no key information.')
                    return ('skipped', "empty_key")

                if message_upsert.key.from_me:
                    logging.warning(f'[{event.event}] Ignoring self-sent message: {message_upsert.key.id}')
                    return ('skipped', "from_me")

                if not message_upsert.key.remote_jid:
                    logging.info(f'[{event.event}] No sender information. ignoring')
                    return ('skipped', "empty_remotejid")
                
                incoming_message_text = None
                message_type = 'unknown'
                if message_upsert.message:
                    if message_upsert.message.conversation:
                        incoming_message_text = message_upsert.message.conversation
                        message_type = 'text'
                    elif event.data['messages']['message'].get('extendedTextMessage'):
                        incoming_message_text = event.data['messages']['message']['extendedTextMessage']['text']
                        message_type = 'text'
                    else:
                        logging.info(f'[{event.event}] Received unimplemented message type. ignoring')
                        return ('skipped', "not_implemented_message_type")
                
                parsed_sender = self.parse_remote_jid(message_upsert.key.remote_jid)

                # Access fields based on chat type
                if parsed_sender.get("chat_type") == "private":
                    phone = parsed_sender.get("phone_number")
                    print(f"Private chat with phone: {phone}")

                elif parsed_sender.get("chat_type") == "group":
                    phone = parsed_sender.get("phone_number")
                    group_id = parsed_sender.get("group_id")
                    print(f"Group chat with phone: {phone}, Group ID: {group_id}")

                elif parsed_sender.get("chat_type") == "unknown":
                    print(f"Unknown chat type: {parsed_sender.get('raw')}")

                elif "error" in parsed_sender:
                    print(f"Error parsing: {parsed_sender.get('error')} - Raw: {parsed_sender.get('raw')}")
                phone_number = message_upsert.key.remote_jid.split('@')[0]
                print(f"suffix: {message_upsert.key.remote_jid.split('@')[1]}")
                logging.info(f'[{event.event}] From: +{phone_number}. Type: {message_type}. Content: {incoming_message_text}')
            case _:
                logging.info(f'[{event.event}] Received unimplemented event type. ignoring')
                return ('skipped', "not_implemented_event_type")
        return ('processed', None)

        payload = json.loads(payload)
        # simulate processing logic
        match payload.get("event"):
            case "messages.upsert":
                
                message = message_data.get('message', {})
                message_content = message.get('conversation') or (message.get('extendedTextMessage') or {}).get('text')
                media_result = find_media_info(message)
                
                if not message_content and not media_result:
                    logging.warning(f"Ignoring event with no content (ID: {message_id})")
                
                logging.info(f"Pre-processing message from {push_name} ({phone_number}). ID: {message_id}")
                updates_dict = self.preprocess_incoming_message(message_content, media_result, message_id)
                for path,value in updates_dict.items():
                    self.update_dict_path(payload, path, value)
                logging.info("Finished pre-processing message")

                data = payload.get("data", {})
            
                raw_messages = data.get("messages")
                messages_to_process = []

                # FIX: Handle both single object and list of objects
                if isinstance(raw_messages, dict):
                    messages_to_process.append(raw_messages)
                elif isinstance(raw_messages, list):
                    messages_to_process = raw_messages
                
                for raw_msg in messages_to_process:
                    # Use our parser to standardize the message
                    parsed_message = self.parse_raw_message(raw_msg)
                    
                    if parsed_message and not parsed_message.get("from_me"):
                        handle_incoming_message(parsed_message)
            case _:
                pass


