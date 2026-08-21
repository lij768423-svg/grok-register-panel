/* Pixel trail / click spark / magnetic — ported from ljj.world (React Bits adaptations). */
(() => {
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)");
  if (reduce.matches) return;

  const css = (name, fallback) =>
    getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;

  initPixelTrail();
  initClickSpark();
  initMagnetic();
  initDecrypt(document.getElementById("kicker"));

  function initPixelTrail() {
    const canvas = document.querySelector(".global-pixel-trail");
    const context = canvas?.getContext("2d");
    if (!canvas || !context) return;

    const CELL = 24;
    const RADIUS = 54;
    const LIFE = 1050;
    const MIN_WIDTH = 900;
    const fine = window.matchMedia("(hover: hover) and (pointer: fine)");

    let state = null;
    let trailColor = css("--kinetic-trail-color", css("--color-accent", "#f06449"));

    const readTheme = () => {
      trailColor = css("--kinetic-trail-color", css("--color-accent", "#f06449"));
    };

    const draw = (timestamp) => {
      if (!state) return;
      const elapsed = state.lastFrameAt > 0 ? Math.min(timestamp - state.lastFrameAt, 200) : 0;
      state.lastFrameAt = timestamp;
      if (state.dirty) {
        const { left, top, right, bottom } = state.dirty;
        context.clearRect(left, top, right - left, bottom - top);
      }

      let visible = false;
      let nextLeft = state.width;
      let nextTop = state.height;
      let nextRight = 0;
      let nextBottom = 0;
      const inset = 1.25;
      context.fillStyle = trailColor;

      for (const index of state.active) {
        const target = Math.max(0, state.targets[index] - elapsed / LIFE);
        const current = state.strengths[index];
        const response = target > current ? 80 : 150;
        const smoothing = 1 - Math.exp(-elapsed / response);
        const strength = current + (target - current) * smoothing;
        state.targets[index] = target;
        state.strengths[index] = strength;
        if (strength <= 0.01 && target <= 0.01) {
          state.active.delete(index);
          continue;
        }
        visible = true;
        const column = index % state.columns;
        const row = Math.floor(index / state.columns);
        const x = column * CELL + inset;
        const y = row * CELL + inset;
        const size = CELL - inset * 2;
        const eased = 1 - (1 - Math.min(strength, 1)) ** 3;
        const texture = 0.82 + ((column * 17 + row * 29) % 11) / 60;
        context.globalAlpha = eased * 0.34 * texture;
        context.fillRect(x, y, size, size);
        nextLeft = Math.min(nextLeft, x);
        nextTop = Math.min(nextTop, y);
        nextRight = Math.max(nextRight, x + size);
        nextBottom = Math.max(nextBottom, y + size);
      }

      context.globalAlpha = 1;
      state.dirty = visible
        ? { left: nextLeft - 1, top: nextTop - 1, right: nextRight + 1, bottom: nextBottom + 1 }
        : null;
      state.frame = visible ? window.requestAnimationFrame(draw) : null;
      if (!visible) state.lastFrameAt = 0;
    };

    const resize = () => {
      const bounds = canvas.getBoundingClientRect();
      const width = Math.max(1, bounds.width);
      const height = Math.max(1, bounds.height);
      if (state?.frame) window.cancelAnimationFrame(state.frame);
      canvas.width = Math.ceil(width);
      canvas.height = Math.ceil(height);
      context.setTransform(1, 0, 0, 1, 0, 0);
      const columns = Math.ceil(width / CELL);
      const rows = Math.ceil(height / CELL);
      state = {
        width,
        height,
        columns,
        rows,
        strengths: new Float32Array(columns * rows),
        targets: new Float32Array(columns * rows),
        active: new Set(),
        dirty: null,
        frame: null,
        lastFrameAt: 0,
        last: null,
      };
    };

    const stamp = (x, y) => {
      if (!state) return;
      const startC = Math.max(0, Math.floor((x - RADIUS) / CELL));
      const endC = Math.min(state.columns - 1, Math.ceil((x + RADIUS) / CELL));
      const startR = Math.max(0, Math.floor((y - RADIUS) / CELL));
      const endR = Math.min(state.rows - 1, Math.ceil((y + RADIUS) / CELL));
      for (let row = startR; row <= endR; row += 1) {
        for (let column = startC; column <= endC; column += 1) {
          const cx = (column + 0.5) * CELL;
          const cy = (row + 0.5) * CELL;
          const distance = Math.hypot(cx - x, cy - y);
          if (distance > RADIUS) continue;
          const strength = Math.min(1, Math.max(0, (1 - distance / RADIUS) * 1.18));
          const index = row * state.columns + column;
          state.targets[index] = Math.max(state.targets[index], strength);
          state.active.add(index);
        }
      }
    };

    const onMove = (event) => {
      if (
        !state
        || !event.isPrimary
        || event.pointerType === "touch"
        || !fine.matches
        || window.innerWidth < MIN_WIDTH
      ) return;

      const bounds = canvas.getBoundingClientRect();
      const x = event.clientX - bounds.left;
      const y = event.clientY - bounds.top;
      if (x < 0 || y < 0 || x > bounds.width || y > bounds.height) {
        state.last = null;
        return;
      }

      const now = performance.now();
      const previous = state.last;
      const interpolate = previous && now - previous.at < 120;
      const distance = interpolate ? Math.hypot(x - previous.x, y - previous.y) : 0;
      const steps = Math.min(24, Math.max(1, Math.ceil(distance / (CELL * 0.55))));
      for (let step = 1; step <= steps; step += 1) {
        const t = step / steps;
        stamp(
          interpolate ? previous.x + (x - previous.x) * t : x,
          interpolate ? previous.y + (y - previous.y) * t : y,
        );
      }
      state.last = { x, y, at: now };
      if (state.frame === null) {
        state.lastFrameAt = now;
        state.frame = window.requestAnimationFrame(draw);
      }
    };

    readTheme();
    resize();
    const themeObserver = new MutationObserver(readTheme);
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    window.addEventListener("resize", resize, { passive: true });
    window.addEventListener("pointermove", onMove, { passive: true });
    window.addEventListener("blur", () => { if (state) state.last = null; });
  }

  function initClickSpark() {
    const canvas = document.querySelector(".click-spark-canvas");
    const context = canvas?.getContext("2d");
    if (!canvas || !context) return;

    const COUNT = 10;
    const DURATION = 520;
    const sparks = [];
    let frame = null;
    let vw = window.innerWidth;
    let vh = window.innerHeight;

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      vw = window.innerWidth;
      vh = window.innerHeight;
      canvas.width = Math.ceil(vw * dpr);
      canvas.height = Math.ceil(vh * dpr);
      context.setTransform(dpr, 0, 0, dpr, 0, 0);
    };

    const draw = (timestamp) => {
      context.clearRect(0, 0, vw, vh);
      const color = css("--color-accent", "#f06449");
      for (let i = sparks.length - 1; i >= 0; i -= 1) {
        const spark = sparks[i];
        const progress = Math.min((timestamp - spark.bornAt) / DURATION, 1);
        if (progress >= 1) {
          sparks.splice(i, 1);
          continue;
        }
        const eased = 1 - (1 - progress) ** 3;
        const distance = 12 + eased * 38;
        const length = 14 * (1 - eased);
        const x = spark.x + Math.cos(spark.angle) * distance;
        const y = spark.y + Math.sin(spark.angle) * distance;
        context.globalAlpha = 1 - progress;
        context.strokeStyle = color;
        context.lineWidth = 1.5;
        context.beginPath();
        context.moveTo(x, y);
        context.lineTo(x + Math.cos(spark.angle) * length, y + Math.sin(spark.angle) * length);
        context.stroke();
      }
      context.globalAlpha = 1;
      frame = sparks.length ? window.requestAnimationFrame(draw) : null;
    };

    window.addEventListener("pointerdown", (event) => {
      if (!event.isPrimary || event.button > 0) return;
      const bornAt = performance.now();
      for (let i = 0; i < COUNT; i += 1) {
        sparks.push({
          x: event.clientX,
          y: event.clientY,
          angle: (Math.PI * 2 * i) / COUNT + (i % 2) * 0.08,
          bornAt,
        });
      }
      if (frame === null) frame = window.requestAnimationFrame(draw);
    }, { passive: true });

    resize();
    window.addEventListener("resize", resize, { passive: true });
  }

  function initMagnetic() {
    const fine = window.matchMedia("(hover: hover) and (pointer: fine)");
    document.querySelectorAll("[data-magnetic]").forEach((el) => {
      let x = 0;
      let y = 0;
      let tx = 0;
      let ty = 0;
      let raf = 0;
      const strength = Number(el.getAttribute("data-magnetic")) || 0.18;

      const tick = () => {
        x += (tx - x) * 0.18;
        y += (ty - y) * 0.18;
        el.style.transform = `translate(${x.toFixed(2)}px, ${y.toFixed(2)}px)`;
        if (Math.abs(tx - x) + Math.abs(ty - y) > 0.04) raf = requestAnimationFrame(tick);
        else raf = 0;
      };

      el.addEventListener("pointermove", (event) => {
        if (event.pointerType === "touch" || !fine.matches) return;
        const box = el.getBoundingClientRect();
        tx = (event.clientX - box.left - box.width / 2) * strength;
        ty = (event.clientY - box.top - box.height / 2) * strength;
        if (!raf) raf = requestAnimationFrame(tick);
      });
      const reset = () => {
        tx = 0;
        ty = 0;
        if (!raf) raf = requestAnimationFrame(tick);
      };
      el.addEventListener("pointerleave", reset);
      el.addEventListener("blur", reset);
    });
  }

  function initDecrypt(node) {
    if (!node) return;
    const target = node.textContent.trim();
    const glyphs = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789#%+/";
    const duration = 640;
    const started = performance.now();
    const tick = (now) => {
      const progress = Math.min(1, (now - started) / duration);
      const keep = Math.floor(progress * target.length);
      let out = target.slice(0, keep);
      for (let i = keep; i < target.length; i += 1) {
        out += target[i] === " " ? " " : glyphs[(Math.floor(now / 40) + i * 7) % glyphs.length];
      }
      node.textContent = out;
      if (progress < 1) requestAnimationFrame(tick);
      else node.textContent = target;
    };
    requestAnimationFrame(tick);
  }
})();
