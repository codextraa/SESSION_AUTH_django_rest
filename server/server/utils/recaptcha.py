from django.conf import settings
from google.cloud import recaptchaenterprise_v1


def verify_recaptcha_token(
    token, expected_action, recaptcha_version, user_ip_address, user_agent
):
    """
    Creates an assessment to analyze the risk of a UI action.
    Returns: (is_valid, error_or_success_message)
    """
    if (
        not token
        and expected_action
        and recaptcha_version
        and user_ip_address
        and user_agent
    ):
        return False, "reCAPTCHA token is missing."

    project_id = settings.RECAPTCHA_PROJECT_ID
    if recaptcha_version == "v2":
        recaptcha_site_key = settings.RECAPTCHA_SITE_KEY_V2
    else:
        recaptcha_site_key = settings.RECAPTCHA_SITE_KEY_V3

    client = recaptchaenterprise_v1.RecaptchaEnterpriseServiceClient()

    event = recaptchaenterprise_v1.Event()
    event.site_key = recaptcha_site_key
    event.token = token
    event.user_ip_address = user_ip_address
    event.user_agent = user_agent

    assessment = recaptchaenterprise_v1.Assessment()
    assessment.event = event

    project_name = f"projects/{project_id}"

    request = recaptchaenterprise_v1.CreateAssessmentRequest()
    request.assessment = assessment
    request.parent = project_name

    response = client.create_assessment(request)

    if not response.token_properties.valid:
        reason = response.token_properties.invalid_reason
        return False, f"Invalid token reason: {reason}"

    if response.token_properties.action != expected_action:
        return (
            False,
            f"Action mismatch. Expected '{expected_action}', got '{response.token_properties.action}'",
        )

    if recaptcha_version == "v2":
        challenge_result = getattr(response.risk_analysis, "challenge", None)
        if challenge_result != recaptchaenterprise_v1.RiskAnalysis.Challenge.PASS:
            return False, "User failed the reCAPTCHA visual challenge."
    else:
        score = response.risk_analysis.score
        if score < 0.7:
            return False, f"High risk transaction blocked. Score: {score}"

    return True, "reCAPTCHA validation successful."
