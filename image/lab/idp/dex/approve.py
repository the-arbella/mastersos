#!/usr/bin/env python3
# The "other device" side of the device flow (Dex → Kanidm): open https://dex.lan:5554/device, enter the code shown on the
# laptop, sign in to Kanidm (user name → password), continue on Kanidm's consent page, back on Dex see the approval.
# Runs on VM 163 in the playwright container (called by approve.sh): approve.py <code> <kanidm user> <shotprefix>;
# the password is read from stdin (never on a command line). Screenshots go to /out/<shotprefix>-*.png.
import re, sys
from playwright.sync_api import sync_playwright
code, user, pre = sys.argv[1:4]
pw = sys.stdin.readline().rstrip("\n")
rules = "MAP dex.lan 127.0.0.1, MAP idm.lan 10.10.10.7"
with sync_playwright() as p:
    b = p.chromium.launch(args=[f"--host-resolver-rules={rules}"])
    pg = b.new_context(ignore_https_errors=True, viewport={"width": 900, "height": 700}).new_page()
    pg.goto("https://dex.lan:5554/device"); pg.wait_for_load_state("networkidle")
    pg.locator("input[name=user_code]").fill(code)
    pg.locator("button[type=submit], input[type=submit]").first.click(); pg.wait_for_load_state("networkidle")
    pg.screenshot(path=f"/out/{pre}-1-after-code.png")
    for i in range(10):
        pg.wait_for_timeout(800)
        body = pg.inner_text("body")
        if re.search(r"(?i)device approved|login successful|you can now|return to your device", body):
            print("APPROVED", pg.url); break
        if pg.locator("input#username:visible, input[name=username]:visible").count():
            e = pg.locator("input#username:visible, input[name=username]:visible").first
            e.fill(user)
            pg.locator("form button[type=submit]:visible").first.click()
        elif pg.locator("input[type=password]:visible").count():
            e = pg.locator("input[type=password]:visible").first
            e.fill(pw)
            pg.locator("form button[type=submit]:visible").first.click()
        else:
            btn = pg.get_by_role("button", name=re.compile(r"proceed|continue|allow|accept|consent|grant|begin|submit", re.I))
            if btn.count(): btn.first.click()
            else:
                print("STUCK", pg.url, body[:300].replace("\n", " | ")); break
        pg.wait_for_load_state("networkidle")
        pg.screenshot(path=f"/out/{pre}-2-step{i}.png")
        print(i, pg.url.split("?")[0], pg.inner_text("body")[:120].replace("\n", " | "))
    b.close()
