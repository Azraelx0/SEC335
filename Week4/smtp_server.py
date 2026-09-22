import asyncio
import email
import os
from aiosmtpd.controller import Controller

class AttachmentHandler:
	async def handle_DATA(self, server, session, envelope):
		msg = email.message_from_bytes(envelope.content)
		for part in msg.walk():
			if part.get_content_disposition() == 'attachment':
				filename = part.get_filename()
				if filename:
					with open(f'/home/kali/loot/{filename}', 'wb') as f:
						f.write(part.get_payload(decode=True))
					print(f'Saved attachment: {filename}')
		return '250 OK'

controller = Controller(AttachmentHandler(), hostname='0.0.0.0', port=25)
controller.start()
print('SMTP server running on port 25...')

try:
	asyncio.get_event_loop().run_forever()
except RuntimeError:
	loop = asyncio.new_event_loop()
	asyncio.set_event_loop(loop)
	loop.run_forever()
