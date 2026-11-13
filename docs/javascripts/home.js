/* Landing page of the SDP research sites (GSAP 3 + ScrollTrigger).
 * Same structure as the SDP Lab and SecureSDP sites; this one animates the
 * session lifecycle of iam-ids-sdp. Without JavaScript all content is visible; with
 * prefers-reduced-motion every figure shows its final state. */
(function () {
  "use strict";
  var root = document.getElementById("lp");
  if (!root) return;
  var gsap = window.gsap;
  if (gsap && window.ScrollTrigger) gsap.registerPlugin(window.ScrollTrigger);
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var animate = !!gsap && !reduce;

  function whenVisible(el, fn, margin) {
    if (!("IntersectionObserver" in window)) { fn(); return; }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { if (e.isIntersecting) { io.disconnect(); fn(); } });
    }, { rootMargin: margin || "0px 0px -10% 0px" });
    io.observe(el);
  }

  /* ---------------- navigation: solid header and section dots ---------------- */
  (function nav() {
    var bar = document.getElementById("lp-nav");
    var onScroll = function () { if (bar) bar.classList.toggle("is-solid", window.scrollY > 24); };
    window.addEventListener("scroll", onScroll, { passive: true });
    onScroll();
    var dots = Array.prototype.slice.call(document.querySelectorAll(".lp-dots a"));
    if (!dots.length || !("IntersectionObserver" in window)) return;
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (!e.isIntersecting) return;
        dots.forEach(function (d) { d.classList.toggle("is-on", d.getAttribute("data-dot") === e.target.id); });
      });
    }, { rootMargin: "-45% 0px -50% 0px" });
    dots.forEach(function (d) {
      var sec = document.getElementById(d.getAttribute("data-dot"));
      if (sec) io.observe(sec);
    });
  })();

  /* ---------------- copy buttons ---------------- */
  root.querySelectorAll("[data-copy], [data-copy-target]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var text = btn.getAttribute("data-copy");
      if (!text) {
        var t = document.getElementById(btn.getAttribute("data-copy-target"));
        text = t ? t.textContent : "";
      }
      if (!navigator.clipboard) return;
      navigator.clipboard.writeText(text.trim()).then(function () {
        var label = btn.textContent;
        btn.textContent = "Copied";
        setTimeout(function () { btn.textContent = label; }, 1500);
      });
    });
  });

  /* ---------------- terminal replay ----------------
   * <pre class="lp-term"> holds one <span class="ln"> per line (visible
   * without JS). When it scrolls into view the lines are replayed. */
  root.querySelectorAll("pre.lp-term").forEach(function (term) {
    if (reduce) return;
    var lines = Array.prototype.slice.call(term.querySelectorAll(".ln"));
    if (!lines.length) return;
    lines.forEach(function (l) { l.style.display = "none"; });
    var cur = document.createElement("span");
    cur.className = "cur";
    cur.textContent = "▋";
    term.appendChild(cur);
    whenVisible(term, function () {
      var i = 0;
      (function next() {
        if (i >= lines.length) { cur.remove(); return; }
        var l = lines[i++];
        l.style.display = "";
        term.insertBefore(cur, l.nextSibling);
        setTimeout(next, l.classList.contains("cmd") ? 650 : 170);
      })();
    });
  });

  /* ---------------- access flow ---------------- */
  var FLOWS = {};

  // iam-ids-sdp: Keycloak, controller and IDS on top; client, gateway and
  // the hidden service below. Login, request, decision, connection,
  // telemetry and revocation.
  var LINKS = ["lp-l-cl-kc", "lp-l-cl-ctrl", "lp-l-ctrl-kc", "lp-l-ctrl-gw", "lp-l-gw-ids", "lp-l-ids-ctrl"];
  FLOWS.iam = {
    finalStep: 4,
    reset: function (q) {
      ["lp-l-cl-gw", "lp-l-gw-svc"].forEach(function (id) { q(id).classList.remove("is-open"); });
      LINKS.forEach(function (id) { q(id).classList.remove("is-active", "is-alert", "is-tel"); });
      ["lp-n-ids", "lp-n-client"].forEach(function (id) { q(id).classList.remove("is-alert", "is-revoked"); });
    },
    final: function (q) {
      ["lp-l-cl-gw", "lp-l-gw-svc"].forEach(function (id) { q(id).classList.add("is-open"); });
      q("lp-l-gw-ids").classList.add("is-tel");
    },
    build: function (tl, q, step, focus) {
      var on = function (id, cls) { tl.call(function () { q(id).classList.add(cls || "is-active"); }); };
      var off = function (id, cls) { tl.call(function () { q(id).classList.remove(cls || "is-active"); }); };
      // 1. MFA login: credentials up, token down
      step(0);
      on("lp-l-cl-kc");
      tl.call(function () { focus("lp-n-client", true); });
      tl.fromTo("#lp-p-login", { attr: { cy: 216 }, opacity: 1 }, { attr: { cy: 106 }, duration: 0.8, ease: "power1.inOut" });
      tl.to("#lp-p-login", { opacity: 0, duration: 0.15 });
      tl.call(function () { focus("lp-n-client", false); focus("lp-n-kc", true); });
      tl.fromTo("#lp-p-token", { attr: { cy: 106 }, opacity: 1 }, { attr: { cy: 216 }, duration: 0.8, ease: "power1.inOut" });
      tl.to("#lp-p-token", { opacity: 0, duration: 0.15 });
      tl.call(function () { focus("lp-n-kc", false); });
      off("lp-l-cl-kc");
      tl.to({}, { duration: 0.4 });
      // 2. SPA + mTLS + token to the controller
      step(1);
      on("lp-l-cl-ctrl");
      tl.call(function () { focus("lp-n-client", true); });
      tl.fromTo("#lp-p-req", { attr: { cx: 180, cy: 218 }, opacity: 1 }, { attr: { cx: 300, cy: 104 }, duration: 1, ease: "power1.inOut" });
      tl.to("#lp-p-req", { opacity: 0, duration: 0.15 });
      tl.call(function () { focus("lp-n-client", false); focus("lp-n-ctrl", true); });
      off("lp-l-cl-ctrl");
      tl.to({}, { duration: 0.3 });
      // 3. introspection, RBAC, keys to the gateway
      step(2);
      on("lp-l-ctrl-kc");
      tl.fromTo("#lp-p-intro", { attr: { cx: 280 }, opacity: 1 }, { attr: { cx: 198 }, duration: 0.6, ease: "power1.inOut" });
      tl.to("#lp-p-intro", { attr: { cx: 280 }, duration: 0.6, ease: "power1.inOut" });
      tl.to("#lp-p-intro", { opacity: 0, duration: 0.15 });
      off("lp-l-ctrl-kc");
      on("lp-l-ctrl-gw");
      tl.fromTo("#lp-p-keys", { attr: { cy: 104 }, opacity: 1 }, { attr: { cy: 216 }, duration: 0.8, ease: "power1.inOut" });
      tl.to("#lp-p-keys", { opacity: 0, duration: 0.15 });
      off("lp-l-ctrl-gw");
      tl.call(function () { focus("lp-n-ctrl", false); });
      tl.to({}, { duration: 0.3 });
      // 4. SPA to the gateway, gate opens, traffic flows
      step(3);
      tl.call(function () { focus("lp-n-client", true); });
      tl.fromTo("#lp-p-spa", { attr: { cx: 197 }, opacity: 1 }, { attr: { cx: 278 }, duration: 0.7, ease: "power2.inOut" });
      tl.to("#lp-p-spa", { opacity: 0, duration: 0.15 });
      tl.call(function () { focus("lp-n-client", false); });
      openGate(tl, q, "lp-n-gw", ["lp-l-cl-gw", "lp-l-gw-svc"], focus);
      tl.call(function () { q("lp-n-svc").classList.add("is-on"); });
      tl.fromTo("#lp-p-data", { attr: { cx: 197 }, opacity: 1 }, { attr: { cx: 462 }, duration: 1.1, ease: "none" });
      tl.to("#lp-p-data", { opacity: 0, duration: 0.15 });
      // 5. telemetry to the IDS while traffic keeps flowing
      step(4);
      on("lp-l-gw-ids", "is-tel");
      tl.fromTo("#lp-p-data", { attr: { cx: 197 }, opacity: 1 }, { attr: { cx: 462 }, duration: 0.9, ease: "none", repeat: 2 });
      tl.fromTo("#lp-p-tel", { attr: { cx: 400, cy: 218 }, opacity: 1 }, { attr: { cx: 505, cy: 104 }, duration: 0.9, ease: "power1.inOut", repeat: 2 }, "<");
      tl.to(["#lp-p-data", "#lp-p-tel"], { opacity: 0, duration: 0.15 });
      // 6. alert and revocation
      step(5);
      tl.call(function () { q("lp-n-ids").classList.add("is-alert"); });
      on("lp-l-ids-ctrl", "is-alert");
      tl.fromTo("#lp-p-alert", { attr: { cx: 462, cy: 72 }, opacity: 1 }, { attr: { cx: 432 }, duration: 0.5, ease: "power1.in" });
      tl.call(function () { focus("lp-n-ctrl", true); });
      on("lp-l-ctrl-gw", "is-alert");
      on("lp-l-ctrl-kc", "is-alert");
      tl.set("#lp-p-alert", { attr: { cx: 355, cy: 104 } });
      tl.to("#lp-p-alert", { attr: { cy: 216 }, duration: 0.7, ease: "power1.inOut" });
      tl.fromTo("#lp-p-intro", { attr: { cx: 280 }, opacity: 1 }, { attr: { cx: 198 }, duration: 0.7, ease: "power1.inOut" }, "<");
      tl.to(["#lp-p-alert", "#lp-p-intro"], { opacity: 0, duration: 0.15 });
      closeGate(tl, q, "lp-n-gw", ["lp-l-cl-gw", "lp-l-gw-svc"], focus);
      tl.call(function () {
        q("lp-n-svc").classList.remove("is-on");
        q("lp-n-client").classList.add("is-revoked");
        q("lp-l-gw-ids").classList.remove("is-tel");
        focus("lp-n-ctrl", false);
      });
      tl.to({}, { duration: 2.2 });
    }
  };

  // shared: the gateway badge turns from locked to open
  function openGate(tl, q, gwId, links, focus) {
    tl.call(function () { focus(gwId, true); q("lp-badge").classList.add("is-open"); });
    tl.to("#lp-badge", { scale: 1.25, transformOrigin: "50% 50%", duration: 0.2, yoyo: true, repeat: 1 });
    tl.to("#lp-badge-closed", { opacity: 0, duration: 0.2 }, "<");
    tl.to("#lp-badge-open", { opacity: 1, duration: 0.2 }, "<");
    tl.call(function () { links.forEach(function (id) { q(id).classList.add("is-open"); }); });
    tl.to({}, { duration: 1.1 });
    tl.call(function () { focus(gwId, false); });
  }



  // shared: the gateway badge turns from open back to locked
  function closeGate(tl, q, gwId, links, focus) {
    tl.call(function () { focus(gwId, true); q("lp-badge").classList.remove("is-open"); links.forEach(function (id) { q(id).classList.remove("is-open"); }); });
    tl.to("#lp-badge", { scale: 1.25, transformOrigin: "50% 50%", duration: 0.2, yoyo: true, repeat: 1 });
    tl.to("#lp-badge-open", { opacity: 0, duration: 0.2 }, "<");
    tl.to("#lp-badge-closed", { opacity: 1, duration: 0.2 }, "<");
    tl.call(function () { focus(gwId, false); });
  }

  (function flow() {
    var svg = root.querySelector(".lp-diagram");
    if (!svg) return;
    var def = FLOWS[svg.getAttribute("data-flow") || "iam"];
    if (!def) return;
    var q = function (id) { return svg.querySelector("#" + id); };
    var buttons = Array.prototype.slice.call(root.querySelectorAll("[data-step]"));
    var caption = document.getElementById("lp-flow-caption");
    var toggle = root.querySelector('[data-flow="toggle"]');
    var restart = root.querySelector('[data-flow="restart"]');
    var status = q("lp-status");
    var labels = buttons.map(function (_, i) { return "s" + i; });

    function setStep(i) {
      buttons.forEach(function (b, j) {
        if (j === i) b.setAttribute("aria-current", "step"); else b.removeAttribute("aria-current");
      });
      var b = buttons[i];
      if (!b) return;
      if (status) status.textContent = b.getAttribute("data-status") || "";
      if (caption) caption.textContent = b.getAttribute("data-caption") || "";
    }
    function focus(id, on) { var n = q(id); if (n) n.classList.toggle("is-focus", on); }
    function finalState() {
      def.final(q);
      var svc = q("lp-n-svc"); if (svc) svc.classList.add("is-on");
      q("lp-badge").classList.add("is-open");
      q("lp-badge-closed").setAttribute("opacity", "0");
      q("lp-badge-open").setAttribute("opacity", "1");
      setStep(def.finalStep != null ? def.finalStep : buttons.length - 1);
    }

    if (!animate) {
      finalState();
      buttons.forEach(function (b, i) { b.addEventListener("click", function () { setStep(i); }); });
      if (toggle) toggle.hidden = true;
      if (restart) restart.hidden = true;
      return;
    }

    var tl = gsap.timeline({ repeat: -1, repeatDelay: 1.2, paused: true });
    tl.call(function () {
      def.reset(q);
      svg.querySelectorAll(".lp-d-node").forEach(function (n) { n.classList.remove("is-focus", "is-on"); });
      q("lp-badge").classList.remove("is-open");
    });
    tl.set(svg.querySelectorAll(".lp-d-pkt, #lp-p-drop"), { opacity: 0 });
    tl.set("#lp-badge-closed", { opacity: 1 });
    tl.set("#lp-badge-open", { opacity: 0 });
    function step(i) { tl.addLabel(labels[i]); tl.call(setStep, [i]); }
    def.build(tl, q, step, focus);

    function setPlaying(p) {
      if (!toggle) return;
      toggle.setAttribute("aria-label", p ? "Pause animation" : "Play animation");
      toggle.textContent = p ? "❚❚" : "▶";
      toggle.dataset.paused = p ? "" : "1";
    }
    buttons.forEach(function (b, i) { b.addEventListener("click", function () { tl.play(labels[i]); setPlaying(true); }); });
    if (toggle) toggle.addEventListener("click", function () {
      if (tl.paused()) { tl.play(); setPlaying(true); } else { tl.pause(); setPlaying(false); }
    });
    if (restart) restart.addEventListener("click", function () { tl.restart(); setPlaying(true); });

    var allowed = function () { return !toggle || !toggle.dataset.paused; };
    if (window.ScrollTrigger) {
      window.ScrollTrigger.create({
        trigger: svg, start: "top 90%", end: "bottom 10%",
        onEnter: function () { if (allowed()) tl.play(); },
        onEnterBack: function () { if (allowed()) tl.play(); },
        onLeave: function () { tl.pause(); },
        onLeaveBack: function () { tl.pause(); }
      });
    } else {
      tl.play();
    }
  })();
})();
