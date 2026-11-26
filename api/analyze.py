from flask import Flask, jsonify, request

from cybershield_server import (
    AnalysisError,
    MAX_MESSAGE_LENGTH,
    MAX_REQUEST_BYTES,
    analyze_with_gemini,
)


app = Flask(__name__)


@app.post("/api/analyze")
def analyze():
    content_length = request.content_length
    if content_length is None:
        return jsonify(error="A request body is required."), 411
    if content_length < 1 or content_length > MAX_REQUEST_BYTES:
        return jsonify(error="The submitted message is too large."), 413

    payload = request.get_json(silent=True)
    text = payload.get("text") if isinstance(payload, dict) else None
    if not isinstance(text, str):
        return jsonify(error="A message or URL is required."), 400

    text = text.strip()
    if len(text) < 5:
        return jsonify(error="Enter at least 5 characters to check."), 400
    if len(text) > MAX_MESSAGE_LENGTH:
        return jsonify(error="The message must be 5000 characters or fewer."), 413

    try:
        return jsonify(analyze_with_gemini(text))
    except AnalysisError as error:
        return jsonify(error=str(error)), error.status
