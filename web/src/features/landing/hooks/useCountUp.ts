import { useEffect, useRef, useState, type RefObject } from "react";

export interface CountUpOptions {
 startOnView?: boolean;
 duration?: number;
 decimals?: number;
 suffix?: string;
 prefix?: string;
}

export function useCountUp(
 target: number,
 options: CountUpOptions = {}
): { count: number; ref: RefObject<HTMLDivElement> } {
 const {
 startOnView = true,
 duration = 2000,
 decimals = 0,
 suffix = "",
 prefix = "",
 } = options;

 const [count, setCount] = useState(0);
 const ref = useRef<HTMLDivElement>(null);
 const started = useRef(false);

 useEffect(() => {
 if (!startOnView) return;
 const el = ref.current;
 if (!el) return;

 const observer = new IntersectionObserver(
 ([entry]) => {
 if (entry.isIntersecting && !started.current) {
 started.current = true;
 animate();
 observer.disconnect();
 }
 },
 { threshold: 0.2 }
 );

 observer.observe(el);
 return () => observer.disconnect();
 }, [target, duration, decimals, suffix, prefix, startOnView]);

 const animate = () => {
 const startTime = performance.now();
 const step = (now: number) => {
 const elapsed = now - startTime;
 const progress = Math.min(elapsed / duration, 1);
 const eased = progress === 1 ? 1 : 1 - Math.pow(2, -10 * progress);
 setCount(eased * target);
 if (progress < 1) requestAnimationFrame(step);
 };
 requestAnimationFrame(step);
 };

 return { count, ref };
}
