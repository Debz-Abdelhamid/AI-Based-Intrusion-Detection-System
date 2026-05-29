import os, time, random, json
from flask import Flask, Response, jsonify, request

CAMERA_ID = os.environ.get("CAMERA_ID", "camera_01")
app = Flask(__name__)

FAKE_JPEG_HEADER = bytes([
    0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46,
    0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
    0x00, 0x01, 0x00, 0x00, 0xFF, 0xD9
])

@app.route("/")
def index():
    return f"""
    <html><body>
    <h2>IP Camera — {CAMERA_ID}</h2>
    <p>Stream: <a href="/stream">/stream</a></p>
    <p>Snapshot: <a href="/snapshot">/snapshot</a></p>
    <p>Info: <a href="/info">/info</a></p>
    </body></html>
    """

@app.route("/info")
def info():
    return jsonify({
        "camera_id": CAMERA_ID,
        "model":     "Yi/Geeni IIoT Camera",
        "firmware":  "2.3.1",
        "uptime_s":  int(time.time() % 86400),
        "resolution":"1920x1080",
        "fps":        15,
        "status":    "recording",
    })

@app.route("/snapshot")
def snapshot():
    frame = FAKE_JPEG_HEADER + bytes(random.getrandbits(8) for _ in range(200))
    return Response(frame, mimetype="image/jpeg")

def mjpeg_generator():
    while True:
        frame = FAKE_JPEG_HEADER + bytes(random.getrandbits(8) for _ in range(200))
        yield (b"--frame\r\nContent-Type: image/jpeg\r\n\r\n" + frame + b"\r\n")
        time.sleep(1 / 15)

@app.route("/stream")
def stream():
    return Response(mjpeg_generator(),
                    mimetype="multipart/x-mixed-replace; boundary=frame")

@app.route("/cgi-bin/admin/param.cgi")
@app.route("/cgi-bin/snapshot.cgi")
def cgi_compat():
    return snapshot()

@app.route("/onvif/device_service", methods=["POST"])
def onvif():
    return Response(
        '<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
        '<s:Body><tds:GetDeviceInformationResponse xmlns:tds="http://www.onvif.org/ver10/device/wsdl">'
        f'<tds:Model>{CAMERA_ID}</tds:Model></tds:GetDeviceInformationResponse></s:Body></s:Envelope>',
        mimetype="text/xml"
    )

def heartbeat():
    import threading
    frames = 0
    while True:
        time.sleep(3)
        frames += 45  # ~15 fps × 3s
        print(f"[{CAMERA_ID}] recording 1920x1080@15fps  frames_encoded={frames}  status=online", flush=True)

if __name__ == "__main__":
    import threading
    print(f"[{CAMERA_ID}] Camera service started on :80", flush=True)
    threading.Thread(target=heartbeat, daemon=True).start()
    app.run(host="0.0.0.0", port=80, threaded=True)
