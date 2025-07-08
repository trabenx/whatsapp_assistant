# whatsapp_client.py
import logging
from wasenderapi import create_sync_wasender
import config

class WhatsAppClient:
    def __init__(self):
        try:
            self.client = create_sync_wasender(
                api_key=config.WASENDER_API_TOKEN,
                webhook_secret=config.WASENDER_WEBHOOK_SECRET
            )
            logging.info("✅ WasenderAPI client initialized successfully.")
        except Exception as e:
            logging.error(f"❌ Failed to initialize WasenderAPI client: {e}")
            raise

    def send_text_message(self, to, message):
        """Sends a simple text message."""
        logging.info(f"-> Sending text to {to}: {message[:50]}...")
        try:
            response = self.client.send_text(to, message)
            logging.info(f"-> Text message sent, response: {response}")
            return response
        except Exception as e:
            logging.error(f"❌ Error sending text message to {to}: {e}")
            return None

    def resend_message(self, recipient_id, original_message):
        """
        Resends a message (text, image, video, etc.) to a new recipient.
        This is the core of the "sync" functionality.
        """
        msg_type = original_message.get("type")
        content = original_message.get("content", {})
        logging.info(f"-> Resending message of type '{msg_type}' to {recipient_id}")

        try:
            if msg_type == "text":
                self.client.send_text(recipient_id, content.get("body"))
            elif msg_type == "image":
                self.client.send_image(
                    recipient_id,
                    content.get("url"),
                    caption=content.get("caption", "")
                )
            elif msg_type == "video":
                self.client.send_video(
                    to=recipient_id,
                    url=content["body"]["url"],
                    caption=content["body"]["caption"]
                    #kwargs=content["body"]
                )
            elif msg_type == "audio":
                self.client.send_audio(recipient_id, content["body"]["url"])
            elif msg_type == "document":
                self.client.send_document(
                    recipient_id,
                    url=content["body"]["url"],
                    filename=content.get("filename", "document")
                )
            else:
                logging.warning(f"-> Unsupported message type for resending: {msg_type}")
                self.send_text_message(
                    config.OWNER_PHONE_NUMBER,
                    f"I couldn't sync the message because its type ('{msg_type}') is not supported yet."
                )
        except Exception as e:
            logging.error(f"❌ Failed to resend message to {recipient_id}: {e}")
            self.send_text_message(
                config.OWNER_PHONE_NUMBER,
                f"I failed to sync the message to {recipient_id}. Please check the logs."
            )

# Create a single instance to be used across the application
client = WhatsAppClient()