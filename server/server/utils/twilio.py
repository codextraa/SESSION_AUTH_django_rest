from twilio.rest import Client
from django.conf import settings
from server.tasks import dispatch_twilio_sms


class TwilioSMS:
    def __init__(self, phone_no, message=None):
        self.client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        self.verify_sid = settings.TWILIO_VERIFY_SERVICE_SID
        self.phone_no = phone_no
        self.message = message

    def send_message(self):
        """Sends custom SMS messages using Twilio Programmable Messaging."""
        if not self.message:
            return {
                "status": "error",
                "message": "Message body is required to send an SMS.",
            }

        dispatch_twilio_sms.delay(self.phone_no, self.message)

        return {
            "status": "success",
            "message": "Message task has been queued.",
        }

    def send_verification(self, channel="sms"):
        """Triggers Twilio Verify to send a managed 6-digit OTP."""
        verification = self.client.verify.v2.services(
            self.verify_sid
        ).verifications.create(to=self.phone_no, channel=channel)

        return {
            "status": "success",
            "sid": verification.sid,
            "verify_status": verification.status,
            "to": verification.to,
        }

    def check_verification(self, code):
        """Checks the OTP submitted by the user against Twilio Verify."""
        if not code:
            return {
                "status": "error",
                "message": "Verification code is required.",
            }

        check = self.client.verify.v2.services(
            self.verify_sid
        ).verification_checks.create(to=self.phone_no, code=code)

        if check.status == "approved":
            return {
                "status": "success",
                "verified": True,
                "check_status": check.status,
            }
        else:
            return {
                "status": "failed",
                "verified": False,
                "check_status": check.status,
                "message": "Invalid or expired verification code.",
            }
