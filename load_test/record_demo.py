"""Record a captioned demo video of the running stack and save screenshots.

Drives Microsoft Edge with Playwright, captures frames through the Chrome DevTools
screencast, and encodes an MP4 with OpenCV (no ffmpeg needed). Captions are drawn into
the page, so they are part of the video. Every request is real: the console talks to the
proxy in Docker; one full request calls Groq (the second one is served from cache).

    python load_test/record_demo.py --out docs/demo
Environment: ADMIN_API_TOKEN (required), CONSOLE_URL, GRAFANA_PASSWORD (default admin).
"""
from __future__ import annotations

import argparse
import base64
import os
import time
from pathlib import Path

import cv2
import numpy as np
from playwright.sync_api import Page, sync_playwright

CONSOLE = os.getenv("CONSOLE_URL", "http://localhost:5173")
ADMIN_TOKEN = os.environ["ADMIN_API_TOKEN"]
GRAFANA_PASSWORD = os.getenv("GRAFANA_PASSWORD", "admin")
SIZE = (1440, 900)
FPS = 10

CAPTION_JS = """
(text) => {
  let bar = document.getElementById('__demo_caption');
  if (!bar) {
    bar = document.createElement('div');
    bar.id = '__demo_caption';
    Object.assign(bar.style, {position: 'fixed', left: '50%', bottom: '28px', transform: 'translateX(-50%)',
      maxWidth: '1100px', width: 'calc(100% - 120px)', zIndex: 2147483647, background: 'rgba(20,33,61,0.94)',
      color: '#fff', font: '500 20px/1.45 "Schibsted Grotesk", "Segoe UI", sans-serif', padding: '14px 22px',
      borderRadius: '8px', boxShadow: '0 6px 24px rgba(0,0,0,.25)', pointerEvents: 'none'});
    document.documentElement.appendChild(bar);
  }
  bar.style.display = text ? 'block' : 'none';
  bar.textContent = text || '';
}
"""


class Recorder:
    """Collects screencast frames and writes them out as a real-time MP4."""

    def __init__(self, page: Page):
        self.page, self.frames, self.started = page, [], time.monotonic()
        self.cdp = page.context.new_cdp_session(page)
        self.cdp.on("Page.screencastFrame", self._frame)
        self.cdp.send("Page.startScreencast", {"format": "jpeg", "quality": 80, "maxWidth": SIZE[0], "maxHeight": SIZE[1]})

    def _frame(self, event):
        self.frames.append((time.monotonic() - self.started, event["data"]))
        try:
            self.cdp.send("Page.screencastFrameAck", {"sessionId": event["sessionId"]})
        except Exception:
            pass

    def save(self, path: Path):
        self.cdp.send("Page.stopScreencast")
        duration = time.monotonic() - self.started
        writer = cv2.VideoWriter(str(path), cv2.VideoWriter_fourcc(*"mp4v"), FPS, SIZE)
        index, current = 0, None
        for tick in range(int(duration * FPS)):
            t = tick / FPS
            while index < len(self.frames) and self.frames[index][0] <= t:
                image = cv2.imdecode(np.frombuffer(base64.b64decode(self.frames[index][1]), np.uint8), cv2.IMREAD_COLOR)
                current = cv2.resize(image, SIZE) if image.shape[1::-1] != SIZE else image
                index += 1
            if current is not None:
                writer.write(current)
        writer.release()
        return duration


class Demo:
    def __init__(self, page: Page, out: Path):
        self.page, self.out = page, out

    def caption(self, text: str, hold: float = 4.0):
        try:
            self.page.evaluate(CAPTION_JS, text)
        except Exception:
            self.page.wait_for_timeout(500)
            self.page.evaluate(CAPTION_JS, text)
        print("caption:", text)
        self.page.wait_for_timeout(int(hold * 1000))

    def shot(self, folder: str, name: str, full_page: bool = False):
        self.page.evaluate(CAPTION_JS, "")
        target = self.out / "screenshots" / folder
        target.mkdir(parents=True, exist_ok=True)
        self.page.screenshot(path=str(target / f"{name}.png"), full_page=full_page)

    def click(self, role: str, name: str, exact: bool = False):
        self.page.get_by_role(role, name=name, exact=exact).first.click()

    def wait_text(self, text: str, timeout: float = 60):
        self.page.get_by_text(text, exact=False).first.wait_for(timeout=int(timeout * 1000))

    def send_and_wait(self, timeout: float = 90):
        self.click("button", "Send through proxy")
        self.page.get_by_role("button", name="Send through proxy").wait_for(timeout=int(timeout * 1000))
        self.page.wait_for_timeout(1200)


def run(out: Path):
    out.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)
        context = browser.new_context(viewport={"width": SIZE[0], "height": SIZE[1]}, device_scale_factor=1)
        page = context.new_page()
        recorder = Recorder(page)
        d = Demo(page, out)

        # --- Inspect -----------------------------------------------------------------------
        page.goto(f"{CONSOLE}/#/inspect")
        page.wait_for_load_state("networkidle")
        d.caption("AI Guardrail Proxy: a security gateway between a company's apps and its LLM providers. "
                  "Everything in this video is a real request to the proxy running in Docker.", 6)
        d.caption("Inspect: pick a scenario, send it through the proxy, and see what every guardrail did to the text.", 4)

        d.click("button", "Customer data in a prompt")
        d.send_and_wait()
        d.caption("Personal data scan: the email, phone number and card were detected. The model would receive "
                  "redaction labels instead of the real values, so the request is allowed.", 6)
        d.shot("01-inspect", "01-personal-data-masked")
        page.mouse.wheel(0, 500)
        d.caption("The checkpoint trace shows each guardrail in the order the proxy runs it: key and limits, "
                  "prompt injection, personal data, policy, model, output redaction.", 5)
        page.mouse.wheel(0, -500)

        d.click("button", "Instruction override")
        d.send_and_wait()
        d.caption("A classic jailbreak: the tripwires catch the phrase (struck through in red) and the request is "
                  "blocked before any model sees it.", 6)
        d.shot("01-inspect", "02-instruction-override-blocked")

        d.click("button", "Injection hidden in a tool result")
        d.send_and_wait()
        d.caption("Indirect injection: the attack hides inside a web page a tool fetched. Tool results are "
                  "scanned too, so this is blocked.", 6)
        d.shot("01-inspect", "03-tool-result-injection-blocked")

        d.click("button", "Hidden characters")
        d.send_and_wait()
        d.caption("Evasion attempt: a zero-width character splits the word 'ignore'. The proxy strips invisible "
                  "characters before matching, so it is still blocked.", 6)
        d.shot("01-inspect", "04-zero-width-evasion-blocked")

        d.click("button", "Attack in Spanish")
        d.send_and_wait()
        d.caption("The same attack in Spanish is caught by the multilingual tripwires.", 4)

        d.click("button", "Ordinary question")
        d.send_and_wait()
        d.caption("A harmless question that mentions 'override' is allowed: the guardrails don't block normal work.", 5)
        d.shot("01-inspect", "05-ordinary-question-allowed")

        d.click("button", "Customer data in a prompt")
        d.click("button", "Full request to the model")
        d.caption("Now a full request: the guardrails, then a real call to Groq (gpt-oss-120b), then output redaction.", 4)
        d.send_and_wait(120)
        page.mouse.wheel(0, 700)
        d.caption("The model only ever saw the masked prompt. Its answer, the tokens used and the cost are shown; "
                  "anything sensitive in the answer is redacted on the way back.", 7)
        d.shot("01-inspect", "06-full-request-groq", full_page=True)
        page.mouse.wheel(0, -700)
        d.send_and_wait(60)
        d.caption("Sending the same prompt again: answered from the exact cache in milliseconds, no model call, no cost.", 6)
        d.shot("01-inspect", "07-exact-cache-hit")

        # --- Tenants and policies ---------------------------------------------------------------------
        page.goto(f"{CONSOLE}/#/tenants")
        page.wait_for_timeout(1500)
        d.caption("Tenants and policies: each customer gets an organization, projects and API keys, managed "
                  "through the admin API. It needs the admin token first.", 5)
        page.get_by_role("button", name="Proxy reachable").click()
        page.get_by_placeholder("ADMIN_API_TOKEN or a gpa_ token").fill(ADMIN_TOKEN)
        page.keyboard.press("Escape")
        page.wait_for_timeout(2000)
        if page.get_by_role("button", name="Create demo tenant").count():
            d.caption("No customers yet. One click creates organization 'acme', project 'support-bot' and an API key "
                      "(only its hash is stored in Postgres).", 4)
            d.click("button", "Create demo tenant")
            d.wait_text("Policy for acme")
        d.caption("The console now sends requests as acme / support-bot (top left). The project's policy is on the "
                  "right of its keys; version history on the far right.", 6)
        d.shot("02-tenants-policies", "01-tenant-and-key")

        page.get_by_role("button", name="Monitor", exact=True).click()
        page.get_by_placeholder("What changed (optional)").fill("Trial run in monitor mode")
        page.get_by_role("button", name="Publish version").click()
        d.wait_text("Published version")
        d.caption("Published version 1 in monitor mode: requests the policy would block are let through and "
                  "recorded, so a customer can roll out safely first.", 6)

        page.goto(f"{CONSOLE}/#/inspect")
        page.wait_for_timeout(800)
        d.click("button", "Instruction override")
        d.send_and_wait()
        d.caption("Same attack under the new policy: 'would block'. Monitor mode let it through but recorded it "
                  "in the audit log.", 6)
        d.shot("02-tenants-policies", "02-monitor-mode-would-block")

        page.goto(f"{CONSOLE}/#/tenants")
        page.wait_for_timeout(1500)
        page.get_by_role("button", name="Enforce", exact=True).click()
        page.get_by_placeholder("What changed (optional)").fill("Enforce after the trial")
        page.get_by_role("button", name="Publish version").click()
        d.wait_text("Published version")
        page.wait_for_timeout(2500)  # replicas pick up policy changes within ~2 s
        d.click("button", "Re-run last prompt")
        page.wait_for_timeout(1500)
        d.caption("Version 2 enforces the policy. Re-running the last prompt now blocks it. Every version is kept "
                  "and can be rolled back with one click.", 7)
        d.shot("02-tenants-policies", "03-enforce-and-versions", full_page=True)

        # --- Agent security --------------------------------------------------------------------------
        page.goto(f"{CONSOLE}/#/agents")
        page.wait_for_timeout(1500)
        d.caption("Agent security: agents read untrusted content and call tools on their own. These checks run "
                  "on every tool call and every answer.", 5)
        add = page.get_by_role("button", name="Add the agent rules")
        if add.count():
            add.click()
            page.wait_for_timeout(1500)
        d.click("button", "Check these calls with the proxy")
        page.wait_for_timeout(1500)
        d.caption("Tool calls: search_orders is allowed; crm_update with a text id breaks its argument schema; the "
                  "SQL injection in a note is denied; delete_customer isn't on the allow-list.", 7)
        d.shot("03-agent-security", "01-tool-calls")
        d.click("button", "Scan this answer")
        page.wait_for_timeout(1500)
        page.get_by_role("heading", name="Leaking links in answers").scroll_into_view_if_needed()
        d.caption("Exfiltration: an image in an answer loads without a click, so its URL can smuggle data out. "
                  "The proxy removes images pointing outside the allowed domain.", 7)
        d.shot("03-agent-security", "02-exfiltration-removed")
        page.get_by_role("heading", name="Repeated attacks lock the session").scroll_into_view_if_needed()
        for _ in range(3):
            d.click("button", "Send an attack")
            page.wait_for_timeout(1200)
        d.click("button", "Send a harmless question")
        page.wait_for_timeout(1500)
        d.caption("Session lock-out: after three attacks in one session (tracked in Redis), even a harmless "
                  "question from that session is refused for 15 minutes.", 7)
        d.shot("03-agent-security", "03-session-locked")

        # --- Observability ---------------------------------------------------------------------------
        page.goto("http://localhost:3000/login")
        page.wait_for_load_state("networkidle")
        if page.locator("input[name='user']").count():
            page.fill("input[name='user']", "admin")
            page.fill("input[name='password']", GRAFANA_PASSWORD)
            page.keyboard.press("Enter")
            page.wait_for_timeout(2500)
            skip = page.get_by_role("button", name="Skip")
            if skip.count():
                skip.click()
        page.goto("http://localhost:3000/d/ai-guardrail-observability?orgId=1&from=now-30m&to=now&refresh=10s")
        page.wait_for_timeout(6000)
        d.caption("Grafana (provisioned automatically): request rate, p95 latency, cache hit rate, security "
                  "events and blocks, errors and cost, from the proxy's Prometheus metrics.", 7)
        d.shot("04-observability", "01-grafana-overview")
        page.mouse.wheel(0, 900)
        page.wait_for_timeout(2500)
        d.caption("Lower panels break traffic, cost, tokens and blocks down by application (tenant) and by model.", 6)
        d.shot("04-observability", "02-grafana-by-app-and-model")

        query = ("sum by (action) (increase(ai_proxy_guardrail_decisions_total[15m]))")
        page.goto(f"http://localhost:9090/graph?g0.expr={query}&g0.tab=1&g0.range_input=15m")
        page.wait_for_timeout(4000)
        d.caption("Prometheus: guardrail decisions in the last 15 minutes by action: allow, flag, block and "
                  "would_block (monitor mode).", 6)
        d.shot("04-observability", "03-prometheus-decisions")

        # Open the slowest recent /generate trace (the one that called the model) by id.
        import httpx

        found = httpx.get("http://localhost:16686/api/traces", timeout=15, params={
            "service": "AI Guardrail Proxy", "operation": "POST /generate", "limit": 20, "lookback": "1h"}).json()
        traces = sorted(found.get("data") or [], key=lambda t: max((s["duration"] for s in t["spans"]), default=0))
        if traces:
            page.goto(f"http://localhost:16686/trace/{traces[-1]['traceID']}")
            page.wait_for_timeout(5000)
            d.caption("Jaeger: one /generate request traced end to end: the security scan, cache lookups, the model "
                      "call to Groq, output redaction and the cache write, with timings.", 8)
            d.shot("04-observability", "04-jaeger-trace")
        else:
            d.caption("Jaeger: traces of each request (security scan, cache, model call, redaction).", 5)
            d.shot("04-observability", "04-jaeger-search")

        page.goto(f"{CONSOLE}/#/inspect")
        page.wait_for_timeout(1500)
        d.caption("That's the AI Guardrail Proxy: prompt-injection and data-leak protection, per-customer "
                  "policies, agent controls and full observability, behind one OpenAI-compatible endpoint.", 6)

        video = out / "guardrail-proxy-demo.mp4"
        seconds = recorder.save(video)
        context.close()
        browser.close()
        print(f"video: {video} ({seconds:.0f} s)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="docs/demo")
    run(Path(parser.parse_args().out))
