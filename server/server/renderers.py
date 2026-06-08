from rest_framework.renderers import JSONRenderer


class ViewRenderer(JSONRenderer):
    """Render Class for All Response."""

    def render(self, data, accepted_media_type=None, renderer_context=None):
        """Render the response data for error handling."""
        response = renderer_context.get("response", None)

        # Check for binary data or non-JSON responses (e.g., images, files)
        if response is not None and (
            response.status_code < 400
            and accepted_media_type
            and "image" in accepted_media_type
        ):
            return data

        if response is not None and response.status_code >= 400:
            if "error" in data:
                data = {"errors": data["error"]}
            if "detail" in data:
                data = {"errors": data["detail"]}
            if "errors" not in data:
                data = {"errors": data}

        return super().render(data, accepted_media_type, renderer_context)
