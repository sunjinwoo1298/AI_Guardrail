"""Turn the recorded demo into web-friendly media for the README.

record_demo.py writes an MPEG-4 Part 2 MP4 (OpenCV's always-available codec), which
browsers and GitHub's player can't play. This writes:
  * guardrail-proxy-demo.webm: VP9, 1280x800, about 30 MB for the ~4 minute demo;
  * demo-preview.gif: one frame every 4 seconds, plays inline in the README.

    python load_test/encode_demo.py --dir docs/demo
VP9 encoding is slow (10-15 minutes for the full demo on a laptop).
"""
from __future__ import annotations

import argparse
import os

import cv2
from PIL import Image

SIZE = (1280, 800)


def encode(folder: str) -> None:
    src = os.path.join(folder, "guardrail-proxy-demo.mp4")
    cap = cv2.VideoCapture(src)
    fps = cap.get(cv2.CAP_PROP_FPS) or 10
    writer = cv2.VideoWriter(os.path.join(folder, "guardrail-proxy-demo.webm"), cv2.CAP_FFMPEG,
                             cv2.VideoWriter_fourcc(*"VP90"), fps, SIZE)
    if not writer.isOpened():
        raise SystemExit("VP9 writer unavailable in this OpenCV build")
    preview, every, index = [], int(fps * 4), 0
    while True:
        ok, frame = cap.read()
        if not ok:
            break
        frame = cv2.resize(frame, SIZE, interpolation=cv2.INTER_AREA)
        writer.write(frame)
        if index % every == 0:
            rgb = cv2.cvtColor(cv2.resize(frame, (960, 600), interpolation=cv2.INTER_AREA), cv2.COLOR_BGR2RGB)
            preview.append(Image.fromarray(rgb).quantize(colors=128, method=Image.Quantize.MEDIANCUT))
        index += 1
    writer.release()
    cap.release()
    if preview:
        preview[0].save(os.path.join(folder, "demo-preview.gif"), save_all=True, append_images=preview[1:],
                        duration=1300, loop=0, optimize=True)
    print(f"encoded {index} frames; gif {len(preview)} frames")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", default="docs/demo")
    encode(parser.parse_args().dir)
