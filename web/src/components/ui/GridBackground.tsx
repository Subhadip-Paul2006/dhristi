// Drishti v0.1 — 21st.dev Favorites Chromatic Mesh & Neural Background Engine | 2026
import React, { useEffect, useRef, useState, type ReactNode } from "react";
import { cn } from "@/lib/utils";

interface Beam {
  type: "h" | "v";
  lineIndex: number;
  pos: number;
  length: number;
  speed: number;
  color: string;
  opacity: number;
}

class Particle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  age: number;
  life: number;
  size: number;
  color: string;

  constructor(w: number, h: number, colors: string[]) {
    this.x = Math.random() * (w || 1000);
    this.y = Math.random() * (h || 800);
    this.vx = (Math.random() - 0.5) * 0.45;
    this.vy = (Math.random() - 0.5) * 0.45;
    this.age = 0;
    this.life = Math.random() * 260 + 140;
    this.size = Math.random() * 1.6 + 0.9;
    this.color = colors[Math.floor(Math.random() * colors.length)];
  }

  update(
    w: number,
    h: number,
    mouse: { x: number; y: number },
    speed: number,
    colors: string[]
  ) {
    const angle = (Math.cos(this.x * 0.003) + Math.sin(this.y * 0.003)) * Math.PI;

    this.vx += Math.cos(angle) * 0.16 * speed;
    this.vy += Math.sin(angle) * 0.16 * speed;

    const dx = mouse.x - this.x;
    const dy = mouse.y - this.y;
    const dist = Math.sqrt(dx * dx + dy * dy);
    const radius = 180;

    if (dist < radius && dist > 0) {
      const force = (radius - dist) / radius;
      this.vx -= (dx / dist) * force * 0.9;
      this.vy -= (dy / dist) * force * 0.9;
    }

    this.x += this.vx;
    this.y += this.vy;
    this.vx *= 0.94;
    this.vy *= 0.94;

    if (this.x < 0) this.x = w;
    if (this.x > w) this.x = 0;
    if (this.y < 0) this.y = h;
    if (this.y > h) this.y = 0;

    this.age++;
    if (this.age > this.life) {
      this.x = Math.random() * w;
      this.y = Math.random() * h;
      this.vx = 0;
      this.vy = 0;
      this.age = 0;
      this.life = Math.random() * 260 + 140;
      this.color = colors[Math.floor(Math.random() * colors.length)];
    }
  }

  draw(ctx: CanvasRenderingContext2D) {
    const progress = this.age / this.life;
    const alpha = Math.sin(progress * Math.PI) * 0.8;

    ctx.save();
    ctx.fillStyle = this.color;
    ctx.globalAlpha = Math.max(0, Math.min(alpha, 1));
    ctx.beginPath();
    ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
    ctx.fill();
    ctx.restore();
  }
}

interface GridBackgroundProps extends React.HTMLAttributes<HTMLDivElement> {
  children?: ReactNode;
  gridSize?: number;
  strokeWidth?: number;
  beamCount?: number;
  particleCount?: number;
  interactive?: boolean;
}

export function GridBackground({
  children,
  className,
  gridSize = 40,
  strokeWidth = 1,
  beamCount = 7,
  particleCount = 220,
  interactive = true,
  ...props
}: GridBackgroundProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [mousePos, setMousePos] = useState({ x: -1000, y: -1000 });

  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animId: number;
    let width = 0;
    let height = 0;

    const resize = () => {
      if (!container || !canvas) return;
      width = container.clientWidth;
      height = container.clientHeight;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      ctx.scale(dpr, dpr);
    };

    const resizeObserver = new ResizeObserver(() => {
      resize();
    });
    resizeObserver.observe(container);
    resize();

    // 21st.dev Favorites Palette: Violet, Indigo, Cyan, Lavender, Emerald
    const particleColors = [
      "#a855f7", // Purple 500
      "#818cf8", // Indigo 400
      "#38bdf8", // Cyan 400
      "#c084fc", // Fuchsia / Lavender
      "#60a5fa", // Blue 400
      "#34d399", // Emerald 400
    ];

    const beamColors = [
      { head: "#c084fc", tail: "rgba(192, 132, 252, 0)" },
      { head: "#818cf8", tail: "rgba(129, 140, 248, 0)" },
      { head: "#38bdf8", tail: "rgba(56, 189, 248, 0)" },
      { head: "#a855f7", tail: "rgba(168, 85, 247, 0)" },
    ];

    const createBeam = (currentWidth: number, currentHeight: number): Beam => {
      const isHorizontal = Math.random() > 0.5;
      const colorScheme = beamColors[Math.floor(Math.random() * beamColors.length)];
      if (isHorizontal) {
        const numLines = Math.max(1, Math.floor(currentHeight / gridSize));
        const lineIndex = Math.floor(Math.random() * numLines) * gridSize;
        const speed = (Math.random() * 1.6 + 1.1) * (Math.random() > 0.5 ? 1 : -1);
        const length = Math.random() * 120 + 80;
        return {
          type: "h",
          lineIndex,
          pos: speed > 0 ? -length : currentWidth + length,
          length,
          speed,
          color: colorScheme.head,
          opacity: Math.random() * 0.5 + 0.5,
        };
      } else {
        const numLines = Math.max(1, Math.floor(currentWidth / gridSize));
        const lineIndex = Math.floor(Math.random() * numLines) * gridSize;
        const speed = (Math.random() * 1.6 + 1.1) * (Math.random() > 0.5 ? 1 : -1);
        const length = Math.random() * 120 + 80;
        return {
          type: "v",
          lineIndex,
          pos: speed > 0 ? -length : currentHeight + length,
          length,
          speed,
          color: colorScheme.head,
          opacity: Math.random() * 0.5 + 0.5,
        };
      }
    };

    const beams: Beam[] = [];
    for (let i = 0; i < beamCount; i++) {
      const b = createBeam(width || 1000, height || 800);
      b.pos = Math.random() * (b.type === "h" ? (width || 1000) : (height || 800));
      beams.push(b);
    }

    const particles: Particle[] = [];
    for (let i = 0; i < particleCount; i++) {
      particles.push(new Particle(width || 1000, height || 800, particleColors));
    }

    const render = () => {
      if (!ctx || width === 0 || height === 0) {
        animId = requestAnimationFrame(render);
        return;
      }

      ctx.clearRect(0, 0, width, height);

      // ── 1. Coordinate Grid with Chromatic Tint ───────────────────────
      ctx.lineWidth = strokeWidth;
      ctx.strokeStyle = "rgba(168, 85, 247, 0.05)";

      ctx.beginPath();
      for (let x = 0; x <= width; x += gridSize) {
        ctx.moveTo(x + 0.5, 0);
        ctx.lineTo(x + 0.5, height);
      }
      for (let y = 0; y <= height; y += gridSize) {
        ctx.moveTo(0, y + 0.5);
        ctx.lineTo(width, y + 0.5);
      }
      ctx.stroke();

      // ── 2. Coordinate Crosshairs at Intersections ────────────────────
      ctx.lineWidth = 1;
      ctx.strokeStyle = "rgba(192, 132, 252, 0.18)";
      const crossSize = 2.5;

      ctx.beginPath();
      for (let x = 0; x <= width; x += gridSize) {
        for (let y = 0; y <= height; y += gridSize) {
          ctx.moveTo(x - crossSize, y);
          ctx.lineTo(x + crossSize, y);
          ctx.moveTo(x, y - crossSize);
          ctx.lineTo(x, y + crossSize);
        }
      }
      ctx.stroke();

      // ── 3. Flow-Field Neural Particles ───────────────────────────────
      particles.forEach((p) => {
        p.update(width, height, mousePos, 0.85, particleColors);
        p.draw(ctx);
      });

      // ── 4. Glowing Grid Beams ────────────────────────────────────────
      beams.forEach((beam, idx) => {
        beam.pos += beam.speed;

        if (
          beam.type === "h" &&
          (beam.speed > 0 ? beam.pos > width + beam.length : beam.pos < -beam.length)
        ) {
          beams[idx] = createBeam(width, height);
          return;
        }
        if (
          beam.type === "v" &&
          (beam.speed > 0 ? beam.pos > height + beam.length : beam.pos < -beam.length)
        ) {
          beams[idx] = createBeam(width, height);
          return;
        }

        const y = beam.lineIndex + 0.5;
        const x = beam.lineIndex + 0.5;

        if (beam.type === "h") {
          const headX = beam.pos;
          const tailX = beam.pos - (beam.speed > 0 ? beam.length : -beam.length);

          const grad = ctx.createLinearGradient(tailX, y, headX, y);
          grad.addColorStop(0, "rgba(168, 85, 247, 0)");
          grad.addColorStop(0.7, `${beam.color}44`);
          grad.addColorStop(1, `${beam.color}`);

          ctx.strokeStyle = grad;
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.moveTo(tailX, y);
          ctx.lineTo(headX, y);
          ctx.stroke();

          ctx.fillStyle = "#ffffff";
          ctx.shadowColor = beam.color;
          ctx.shadowBlur = 10;
          ctx.beginPath();
          ctx.arc(headX, y, 1.8, 0, Math.PI * 2);
          ctx.fill();
          ctx.shadowBlur = 0;
        } else {
          const headY = beam.pos;
          const tailY = beam.pos - (beam.speed > 0 ? beam.length : -beam.length);

          const grad = ctx.createLinearGradient(x, tailY, x, headY);
          grad.addColorStop(0, "rgba(168, 85, 247, 0)");
          grad.addColorStop(0.7, `${beam.color}44`);
          grad.addColorStop(1, `${beam.color}`);

          ctx.strokeStyle = grad;
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.moveTo(x, tailY);
          ctx.lineTo(x, headY);
          ctx.stroke();

          ctx.fillStyle = "#ffffff";
          ctx.shadowColor = beam.color;
          ctx.shadowBlur = 10;
          ctx.beginPath();
          ctx.arc(x, headY, 1.8, 0, Math.PI * 2);
          ctx.fill();
          ctx.shadowBlur = 0;
        }
      });

      // ── 5. Cursor Interactive Glow ───────────────────────────────────
      if (mousePos.x > 0 && mousePos.y > 0) {
        const radGrad = ctx.createRadialGradient(
          mousePos.x,
          mousePos.y,
          0,
          mousePos.x,
          mousePos.y,
          240
        );
        radGrad.addColorStop(0, "rgba(168, 85, 247, 0.14)");
        radGrad.addColorStop(0.5, "rgba(99, 102, 241, 0.03)");
        radGrad.addColorStop(1, "rgba(168, 85, 247, 0)");

        ctx.fillStyle = radGrad;
        ctx.fillRect(mousePos.x - 240, mousePos.y - 240, 480, 480);
      }

      animId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animId);
      resizeObserver.disconnect();
    };
  }, [gridSize, strokeWidth, beamCount, particleCount, mousePos]);

  useEffect(() => {
    if (!interactive) return;
    const container = containerRef.current;
    if (!container) return;

    const handleMouseMove = (e: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      setMousePos({
        x: e.clientX - rect.left,
        y: e.clientY - rect.top,
      });
    };

    const handleMouseLeave = () => {
      setMousePos({ x: -1000, y: -1000 });
    };

    container.addEventListener("mousemove", handleMouseMove);
    container.addEventListener("mouseleave", handleMouseLeave);

    return () => {
      container.removeEventListener("mousemove", handleMouseMove);
      container.removeEventListener("mouseleave", handleMouseLeave);
    };
  }, [interactive]);

  return (
    <div
      ref={containerRef}
      className={cn(
        "relative w-full h-full min-h-full overflow-hidden text-ink",
        className
      )}
      style={{
        background:
          "radial-gradient(135% 100% at 50% -10%, #150d2a 0%, #0a0817 40%, #030208 100%)",
      }}
      {...props}
    >
      {/* 21st.dev Favorites Multi-Mesh Aurora Gradient Blooms */}
      <div
        aria-hidden="true"
        className="absolute -top-40 left-1/2 -translate-x-1/2 w-full max-w-7xl h-[550px] pointer-events-none z-0"
        style={{
          background:
            "radial-gradient(ellipse 70% 55% at 50% 0%, rgba(168, 85, 247, 0.22), rgba(99, 102, 241, 0.12) 45%, transparent 75%)",
        }}
      />
      <div
        aria-hidden="true"
        className="absolute top-1/4 -left-32 w-[520px] h-[520px] pointer-events-none z-0 rounded-full"
        style={{
          background:
            "radial-gradient(circle, rgba(56, 189, 248, 0.12) 0%, rgba(99, 102, 241, 0.04) 50%, transparent 70%)",
        }}
      />
      <div
        aria-hidden="true"
        className="absolute top-1/3 -right-32 w-[520px] h-[520px] pointer-events-none z-0 rounded-full"
        style={{
          background:
            "radial-gradient(circle, rgba(236, 72, 153, 0.09) 0%, rgba(168, 85, 247, 0.03) 50%, transparent 70%)",
        }}
      />

      {/* Dynamic Animated Canvas Layer (Neural Flow Particles + Grid Beams) */}
      <canvas
        ref={canvasRef}
        className="absolute inset-0 pointer-events-none z-0 block w-full h-full"
      />

      {/* Smooth Vignette for Content Readability */}
      <div
        aria-hidden="true"
        className="absolute inset-0 pointer-events-none z-0"
        style={{
          background:
            "radial-gradient(circle at 50% 40%, transparent 45%, rgba(3, 2, 8, 0.72) 100%)",
        }}
      />

      {/* Foreground Content */}
      <div className="relative z-10 w-full h-full flex flex-col">{children}</div>
    </div>
  );
}

export default GridBackground;
