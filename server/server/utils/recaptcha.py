import logging
from django.conf import settings
from google.cloud import recaptchaenterprise_v1

logger = logging.getLogger(__name__)


def verify_recaptcha_token(
    token, expected_action, recaptcha_version, user_ip_address, user_agent
):
    """
    Creates an assessment to analyze the risk of a UI action.
    Returns: (is_valid, error_or_success_message)
    """
    project_id = settings.RECAPTCHA_PROJECT_ID
    if recaptcha_version == "v2":
        recaptcha_site_key = (
            settings.RECAPTCHA_SITE_KEY_V2
        )  # frontend uses this to generate the recaptcha token
    else:
        recaptcha_site_key = settings.RECAPTCHA_SITE_KEY_V3

    client = (
        recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient()
    )  # recaptcha's backend client

    event = recaptchaenterprise_v1.Event()  # we add token, attributes here
    event.site_key = recaptcha_site_key
    event.token = token
    event.user_ip_address = user_ip_address
    event.user_agent = user_agent

    assessment = (
        recaptchaenterprise_v1.Assessment()
    )  # made an assessment object and added event to it, which will be sent to recaptcha's backend for verification
    assessment.event = event

    project_name = f"projects/{project_id}"

    request = recaptchaenterprise_v1.CreateAssessmentRequest()
    request.assessment = assessment
    request.parent = project_name

    response = client.create_assessment(
        request
    )  # response from recaptcha's backend after verification

    if not response.token_properties.valid:
        reason = response.token_properties.invalid_reason
        return False, f"Invalid token reason: {reason}"

    if response.token_properties.action != expected_action:
        return (
            False,
            f"Action mismatch. Expected '{expected_action}', got '{response.token_properties.action}'",
        )

    score = response.risk_analysis.score

    if score < 0.7:
        logger.error(f"High risk transaction blocked. Score: {score}")
        return False, "reCAPTCHA validation failed."

    return True, "reCAPTCHA validation successful."
